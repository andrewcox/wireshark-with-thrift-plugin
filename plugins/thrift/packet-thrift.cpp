/**
 * packet-thrift.c
 * Routines for thrift protocol dissection.
 * By: John Song <jsong@facebook.com>
 * By: Bill Fumerola <bill@facebook.com>
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
USA.
 */
extern "C" {
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

#define _U_

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/xdlc.h>
#include <epan/dissectors/packet-tcp.h>

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif
}

#include "packet-thrift.h"

#ifndef __BYTE_ORDER
# if defined(BYTE_ORDER) && defined(LITTLE_ENDIAN) && defined(BIG_ENDIAN)
#  define __BYTE_ORDER BYTE_ORDER
#  define __LITTLE_ENDIAN LITTLE_ENDIAN
#  define __BIG_ENDIAN BIG_ENDIAN
# else
#  error "Cannot determine endianness"
# endif
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#  define ntohll(n) (n)
#  define htonll(n) (n)
# if defined(__GNUC__) && defined(__GLIBC__)
#  include <byteswap.h>
#  define htolell(n) bswap_64(n)
#  define letohll(n) bswap_64(n)
# else /* GNUC & GLIBC */
#  define bswap_64(n) \
      ( (((n) & 0xff00000000000000ull) >> 56) \
      | (((n) & 0x00ff000000000000ull) >> 40) \
      | (((n) & 0x0000ff0000000000ull) >> 24) \
      | (((n) & 0x000000ff00000000ull) >> 8)  \
      | (((n) & 0x00000000ff000000ull) << 8)  \
      | (((n) & 0x0000000000ff0000ull) << 24) \
      | (((n) & 0x000000000000ff00ull) << 40) \
      | (((n) & 0x00000000000000ffull) << 56) )
#  define htolell(n) bswap_64(n)
#  define letohll(n) bswap_64(n)
# endif /* GNUC & GLIBC */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#  define htolell(n) (n)
#  define letohll(n) (n)
# if defined(__GNUC__) && defined(__GLIBC__)
#  include <byteswap.h>
#  define ntohll(n) bswap_64(n)
#  define htonll(n) bswap_64(n)
# else /* GNUC & GLIBC */
#  define ntohll(n) ( (((unsigned long long)ntohl(n)) << 32) + ntohl(n >> 32) )
#  define htonll(n) ( (((unsigned long long)htonl(n)) << 32) + htonl(n >> 32) )
# endif /* GNUC & GLIBC */
#else /* __BYTE_ORDER */
# error "Can't define htonll or ntohll!"
#endif

#define THRIFT_PORT 18888

/* copy from thrift TProtocol.h */
static const int32_t VERSION_MASK = 0xffff0000;
static const int32_t VERSION_1 = 0x80010000;

/**
 * Enumerated definition of the types that the Thrift protocol supports.
 * Take special note of the T_END type which is used specifically to mark
 * the end of a sequence of fields.
 **/
typedef enum TType_enum {
  T_STOP       = 0,
  T_VOID       = 1,
  T_BOOL       = 2,
  T_BYTE       = 3,
  T_I08        = 3,
  T_I16        = 6,
  T_I32        = 8,
  T_U64        = 9,
  T_I64        = 10,
  T_DOUBLE     = 4,
  T_STRING     = 11,
  T_UTF7       = 11,
  T_STRUCT     = 12,
  T_MAP        = 13,
  T_SET        = 14,
  T_LIST       = 15,
  T_UTF8       = 16,
  T_UTF16      = 17
} TType;

/**
 * Enumerated definition of the message types that the Thrift protocol
 * supports.
 */
enum TMessageType {
  T_NONE       = 0,
  T_CALL       = 1,
  T_REPLY      = 2,
  T_EXCEPTION  = 3,
  T_ONEWAY     = 4
};

/* Initialize the protocol and registered fields */
int proto_thrift = -1;

int hf_thrift_bool = -1;
int hf_thrift_byte = -1;
int hf_thrift_int16 = -1;
int hf_thrift_int32 = -1;
int hf_thrift_int64 = -1;
int hf_thrift_double = -1;
int hf_thrift_string = -1;
//int hf_thrift_binary = -1;
int hf_thrift_struct = -1;
int hf_thrift_message = -1;
int hf_thrift_list = -1;
int hf_thrift_map = -1;
int hf_thrift_map_entry = -1;
int hf_thrift_set = -1;

/* Initialize the subtree pointers */
gint ett_thrift_struct = -1;
gint ett_thrift_list = -1;
gint ett_thrift_map = -1;
gint ett_thrift_map_entry = -1;
gint ett_thrift_set = -1;
gint ett_thrift_message = -1;

/*********************  Function Declaration *********************/
extern "C" void proto_register_thrift(void);
extern "C" void proto_reg_handoff_thrift(void);
static gint dissect_message(tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_bool(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_byte(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_int16(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_int32(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_int64(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_double(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_string(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_bytype(const char * prefix, TType type, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_list(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_struct(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_map(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_set(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent);
static gint dissect_exception(const char* prefix, tvbuff_t* tvb, gint *offset, packet_info* pinfo, proto_tree* parent);
static gboolean dissect_thrift(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root);

/*********************  Function Definition *********************/

static gint dissect_message(tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent) {
  gint count = 0;
  bool isrequest = true;
  guint32 sz = 0;
  guint32 seqid = 0;
  guint8* str = NULL;
  guint32 ver = 0;
  guint32 mtype = 0;
  proto_item* ti = NULL;
  proto_tree* tree = NULL;
  gint n = 0;
  guint32 header = 0;
  gint start = *offset;

  /* read 4 byte frame size */
  header = tvb_get_ntohl(tvb, *offset);
  *offset += 4;
  count += 4;

  /* TODO: Read header */

  /* TODO: Unapply any transforms (e.g. compression) indicated
   * in the header */

  while (true) {
    /* Read 4 byte version */
    header = tvb_get_ntohl(tvb, *offset);
    *offset += 4;
    count += 4;

    ver = (guint32)(header & VERSION_MASK);
    mtype = (guint32)(header & 0x000000ff);

    if (ver == (guint32)VERSION_1) {
      break;
    }
  }

  /* read string length of method name */
  sz = tvb_get_ntohl(tvb, *offset);
  *offset += 4;
  count += 4;

  /* read a string for method name */
  str = tvb_get_string(tvb, *offset, sz);
  *offset += sz;
  count += sz;

  /* read an int32 seqid */
  seqid = tvb_get_ntohl(tvb, *offset);
  *offset += 4;
  count += 4;

  ti = proto_tree_add_item(parent, hf_thrift_message, tvb, start, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_thrift_message);
  switch (mtype) {
  case T_CALL:
    proto_item_set_text(ti, "Request[version:%x, type:%d, seqid:%d, method:%s]", ver, mtype, seqid, str);
    n = dissect_struct("", tvb, offset, pinfo, tree);
    break;
  case T_REPLY:
    proto_item_set_text(ti, "Reply[version:%x, mtype:%d, seqid:%d, method:%s]", ver, mtype, seqid, str);
    isrequest = false;
    n = dissect_struct("", tvb, offset, pinfo, tree);
    break;
  case T_ONEWAY:
    proto_item_set_text(ti, "Request[oneway: true, version:%x, mtype:%d, seqid:%d, method:%s]", ver, mtype, seqid, str);
    n = dissect_struct("", tvb, offset, pinfo, tree);
    break;
  case T_EXCEPTION:
    proto_item_set_text(ti, "Exception[version:%x, mtype:%d, seqid:%d, method:%s]", ver, mtype, seqid, str);
    isrequest = false;
    n = dissect_exception("", tvb, offset, pinfo, tree);
    break;
  }

  *offset += n;
  count += n;

  proto_item_set_len(ti, count);

  /* set direction column */
  if (check_col(pinfo->cinfo, COL_IF_DIR)) {
    col_set_str(pinfo->cinfo, COL_IF_DIR, (isrequest ? "IN" : "OUT"));
  }

  g_free(str);

  return count;
}

static gint dissect_bool(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo _U_, proto_tree* parent) {
  guint8 v = 0;
  proto_item* ti = NULL;

  v = tvb_get_guint8(tvb, *offset);

  ti = proto_tree_add_item(parent, hf_thrift_bool, tvb, *offset, 1, FALSE);
  proto_item_set_text(ti, "%sBoolan: %s", prefix, (v ? "TRUE" : "FALSE"));

  *offset += 1;
  return 1;
}

static gint dissect_byte(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo _U_, proto_tree* parent) {
  guint8 v = 0;
  proto_item* ti = NULL;

  v = tvb_get_guint8(tvb, *offset);

  ti = proto_tree_add_item(parent, hf_thrift_byte, tvb, *offset, 1, FALSE);
  proto_item_set_text(ti, "%sByte: %x", prefix, v);

  *offset += 1;
  return 1;
}

static gint dissect_int16(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo _U_, proto_tree* parent) {
  guint16 v = 0;
  proto_item* ti = NULL;

  v = tvb_get_ntohs(tvb, *offset);

  ti = proto_tree_add_item(parent, hf_thrift_int16, tvb, *offset, 2, FALSE);
  proto_item_set_text(ti, "%sInt16: %d", prefix, v);

  *offset += 2;
  return 2;
}

static gint dissect_int32(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo _U_, proto_tree* parent) {
  guint32 v = 0;
  proto_item* ti = NULL;

  v = tvb_get_ntohl(tvb, *offset);

  ti = proto_tree_add_item(parent, hf_thrift_int32, tvb, *offset, 4, FALSE);
  proto_item_set_text(ti, "%sInt32: %d", prefix, v);

  *offset += 4;

  return 4;
}

static gint dissect_int64(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo _U_, proto_tree* parent) {
  guint64 v = 0;
  proto_item* ti = NULL;

  v = tvb_get_ntoh64(tvb, *offset);
  ti = proto_tree_add_item(parent, hf_thrift_int64, tvb, *offset, 8, FALSE);
  proto_item_set_text(ti, "%sInt64: %lld", prefix, v);

  *offset += 8;

  return 8;
}

static gint dissect_double(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo _U_, proto_tree* parent) {
  proto_item* ti = NULL;
  gdouble d = 0;

  d = tvb_get_ntohieee_double(tvb, *offset);

  ti = proto_tree_add_item(parent, hf_thrift_double, tvb, *offset, 8, FALSE);
  proto_item_set_text(ti, "%sDouble: %lf", prefix, d);

  *offset += 8;

  return 8;
}

static gint dissect_string(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo _U_, proto_tree* parent) {
  guint32 sz = 0;
  guint8* str = NULL;
  gint count = 0;
  proto_item* ti = NULL;

  /* get size */
  sz = tvb_get_ntohl(tvb, *offset);
  *offset += 4;
  count += 4;

  /* read in string */
  str = tvb_get_string(tvb, *offset, sz);
  count += sz;
  *offset += sz;
  ti = proto_tree_add_item(parent, hf_thrift_string, tvb, *offset - count, count, FALSE);
  proto_item_set_text(ti, "%sString: %s", prefix, str);

  g_free(str);

  return count;
}

static gint dissect_bytype(const char * prefix, TType type, tvbuff_t* tvb, gint* offset, packet_info* pinfo _U_, proto_tree* parent) {
  gint n = 0;

  switch (type) {
    case T_STOP:
      break;
    case T_VOID:
      break;
    case T_BOOL:
      n += dissect_bool(prefix, tvb, offset, pinfo, parent);
      break;
    case T_BYTE:
    /* case T_I08: */
      n += dissect_byte(prefix, tvb, offset, pinfo, parent);
      break;
    case T_I16:
      n += dissect_int16(prefix, tvb, offset, pinfo, parent);
      break;
    case T_I32:
      n += dissect_int32(prefix, tvb, offset, pinfo, parent);
      break;
    case T_U64:
      n += dissect_int64(prefix, tvb, offset, pinfo, parent);
      break;
    case T_I64:
      n += dissect_int64(prefix, tvb, offset, pinfo, parent);
      break;
    case T_DOUBLE:
      n += dissect_double(prefix, tvb, offset, pinfo, parent);
      break;
    case T_STRING:
    /* case T_UTF7: */
      n += dissect_string(prefix, tvb, offset, pinfo, parent);
      break;
    case T_STRUCT:
      n += dissect_struct(prefix, tvb, offset, pinfo, parent);
      break;
    case T_MAP:
      n += dissect_map(prefix, tvb, offset, pinfo, parent);
      break;
    case T_SET:
      n += dissect_set(prefix, tvb, offset, pinfo, parent);
      break;
    case T_LIST:
      n += dissect_list(prefix, tvb, offset, pinfo, parent);
      break;
    case T_UTF8:
      n += dissect_string(prefix, tvb, offset, pinfo, parent);
      break;
    case T_UTF16:
      break;
  }

  return n;
}

static gint dissect_list(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo _U_, proto_tree* parent) {
  gint count = 0;
  TType type = (TType)0;
  guint32 sz = 0;
  unsigned int i;
  proto_item* ti = NULL;
  proto_tree* tree = NULL;
  gint n = 0;

  /* get type */
  type = (TType)tvb_get_guint8(tvb, *offset);
  count += 1;
  *offset += 1;

  /* get size */
  sz = tvb_get_ntohl(tvb, *offset);
  *offset += 4;
  count += 4;

  ti = proto_tree_add_item(parent, hf_thrift_list, tvb, *offset - count, -1, FALSE);
  proto_item_set_text(ti, "%sList[%d]", prefix, sz);
  tree = proto_item_add_subtree(ti, ett_thrift_list);

  for (i = 0; i < sz; ++i) {
    n = dissect_bytype(prefix, type, tvb, offset, pinfo, tree);
    count += n;
  }

  /* set length for the list element */
  proto_item_set_len(ti, count);

  return count;
}

static gint dissect_exception(const char* prefix, tvbuff_t* tvb, gint *offset, packet_info* pinfo _U_, proto_tree* parent) {
  gint count = 0;
  guint8 type = 0;
  guint32 sz = 0;
  proto_item* ti = NULL;
  guint16 fid = 0;
  guint32 errcode = 0;
  guint8* errmsg = NULL;

  ti = proto_tree_add_item(parent, hf_thrift_struct, tvb, *offset, -1, FALSE);

  /* read struct begin */

  while (true) {
    /* read field begin */
    type = tvb_get_guint8(tvb, *offset);
    *offset += 1;
    count += 1;

    if ((TType)type == T_STOP) {
      break;
    }

    /* read in field id */
    fid = tvb_get_ntohs(tvb, *offset);
    *offset += 2;
    count += 2;

    /* id: 1 is string and 2 is uint32 */
    if (fid == 1) {
      /* get size */
      sz = tvb_get_ntohl(tvb, *offset);
      *offset += 4;
      count += 4;

      /* read in string */
      errmsg = tvb_get_string(tvb, *offset, sz);
      *offset += sz;
      count += sz;
    } else if (fid == 2) {
      errcode = tvb_get_ntohl(tvb, *offset);
      *offset += 4;
      count += 4;
    }
    /* read field end */
  }

  /* read struct end */

  /* set struct len */
  proto_item_set_len(ti, count);

  proto_item_set_text(ti, "%sException(%d): %s", prefix, errcode, errmsg);

  g_free(errmsg);

  return count;
}


static gint dissect_struct(const char* prefix, tvbuff_t* tvb, gint *offset, packet_info* pinfo, proto_tree* parent) {
  gint count = 0;
  TType type = (TType)0;
  proto_item* ti = NULL;
  proto_tree* tree = NULL;
  guint16 fid = 0;
  char buf[1024];

  ti = proto_tree_add_item(parent, hf_thrift_struct, tvb, *offset, -1, FALSE);
  proto_item_set_text(ti, "%sStruct", prefix);
  tree = proto_item_add_subtree(ti, ett_thrift_struct);

  /* read struct begin */

  while (true) {
    /* read field begin */
    type = (TType)tvb_get_guint8(tvb, *offset);
    *offset += 1;
    count += 1;
    if (type == T_STOP) {
      break;
    }

    /* read in field id */
    fid = tvb_get_ntohs(tvb, *offset);
    *offset += 2;
    count += 2;
    /* field id prefix */
    g_snprintf(buf, sizeof(buf), "%u.", fid);

    /* process field */
    count += dissect_bytype("", type, tvb, offset, pinfo, tree);

    /* read field end */
  }

  /* read struct end */

  /* set struct len */
  proto_item_set_len(ti, count);

  return count;
}

static gint dissect_map(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent) {
  gint count = 0;
  TType keytype = (TType)0;
  TType valtype = (TType)0;
  proto_item* ti = NULL;
  proto_tree* tree = NULL;
  guint32 sz = 0;
  unsigned int i;

  ti = proto_tree_add_item(parent, hf_thrift_map, tvb, *offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_thrift_map);

  /* read map begin */
  keytype = (TType)tvb_get_guint8(tvb, *offset);
  *offset += 1;
  count += 1;

  valtype = (TType)tvb_get_guint8(tvb, *offset);
  *offset += 1;
  count += 1;

  sz = tvb_get_ntohl(tvb, *offset);
  *offset += 4;
  count += 4;

  proto_item_set_text(ti, "%sMap<%d, %d>", prefix, keytype, valtype);

  for (i = 0; i < sz; ++i) {
    count += dissect_bytype("key: ", keytype, tvb, offset, pinfo, tree);
    count += dissect_bytype("val: ", valtype, tvb, offset, pinfo, tree);
  }

  /* read map end */

  proto_item_set_len(ti, count);

  return count;
}

static gint dissect_set(const char* prefix, tvbuff_t* tvb, gint* offset, packet_info* pinfo, proto_tree* parent) {
  gint count = 0;
  TType type = (TType)0;
  guint32 sz = 0;
  unsigned int i;
  proto_item* ti = NULL;
  proto_tree* tree = NULL;

  type = (TType)tvb_get_guint8(tvb, *offset);
  count += 1;
  *offset += 1;

  sz = tvb_get_ntohl(tvb, *offset);
  *offset += 4;
  count += 4;

  ti = proto_tree_add_item(parent, hf_thrift_list, tvb, *offset, -1, FALSE);
  proto_item_set_text(ti, "%sSet(%d)", prefix, sz);
  tree = proto_item_add_subtree(ti, ett_thrift_set);

  for (i = 0; i < sz; ++i) {
    count += dissect_bytype(prefix, type, tvb, offset, pinfo, tree);
  }

  /* set length for the list element */
  proto_item_set_len(ti, count);

  return count;
}

static void dissect_thrift_message(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root) {
  gint count = 0;
  gboolean success;
  success = dissect_message( tvb, &count, pinfo, root );
}

static guint get_thrift_message_len(packet_info* pinfo, tvbuff_t* tvb, int offset) {
  guint message_len = (guint)tvb_get_ntohl(tvb, offset);
  /* This method must return the length of the frame, *including* the frame size part */
  return sizeof(guint) + message_len;
}

/* dissect thrift */
static gboolean dissect_thrift(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root) {

#if 0

  gint count = 0;
  gboolean success = FALSE;

  TRY {
    /* Try parsing the TMessage, possibly reading across multiple packets to
     * reassemble it */
    tcp_dissect_pdus(tvb, pinfo, root, TRUE, 4, get_thrift_message_len, dissect_thrift_message);

    if (root) {
      if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Thrift");
      }

      /* if (check_col(pinfo->cinfo, COL_INFO)) { */
      /* 	col_clear(pinfo->cinfo, COL_INFO); */
      /* } */
    }

    /* Parse successful, message is Thrift */
    success = TRUE;
  }
  CATCH_ALL {
    /* Something went wrong in parsing, assume this isn't a Thrift message */
  }
  ENDTRY;

  return success;

#else

  return try_dissect_thrift_message(tvb, pinfo, root);

#endif

}

static void dissect_thrift_void(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root) {
  dissect_thrift(tvb, pinfo, root);
}

void proto_register_thrift(void) {

  static hf_register_info hf[] = {
    {
      &hf_thrift_bool,
      {
        "Boolean",
        "thrift.bool",
        FT_BOOLEAN,
        8,
        NULL,
        0,
        "Thrift boolean Datatype",
        HFILL
      }
    },
    {
      &hf_thrift_byte,
      {
        "Byte",
        "thrift.byte",
        FT_UINT8,
        BASE_HEX,
        NULL,
        0,
        "Thrift byte datatype",
        HFILL
      }
    },
    {
      &hf_thrift_int16,
      {
        "Int16",
        "thrift.int16",
        FT_UINT16,
        BASE_DEC,
        NULL,
        0,
        "Thrift int16 datatype",
        HFILL
      }
    },
    {
      &hf_thrift_int32,
      {
        "Int32",
        "thrift.int32",
        FT_NONE,
        BASE_NONE,
        NULL,
        0,
        "Thrift int32 datatype",
        HFILL
      }
    },
    {
      &hf_thrift_int64,
      {
        "Int64",
        "thrift.int64",
        FT_UINT64,
        BASE_DEC,
        NULL,
        0,
        "Thrift int64 datatype",
        HFILL
      }
    },
    {
      &hf_thrift_double,
      {
        "Double",
        "thrift.double",
        FT_DOUBLE,
        BASE_NONE,
        NULL,
        0,
        "Thrift double datatype",
        HFILL
      }
    },
    {
      &hf_thrift_string,
      {
        "String",
        "thrift.string",
        FT_NONE,
        BASE_NONE,
        NULL,
        0,
        "Thrift string datatype",
        HFILL
      }
    },
    {
      &hf_thrift_struct,
      {
        "Struct",
        "thrift.struct",
        FT_NONE,
        BASE_NONE,
        NULL,
        0,
        "Thrift struct datatype",
        HFILL
      }
    },
    {
      &hf_thrift_message,
      {
        "Messsage",
        "thrift.message",
        FT_NONE,
        BASE_NONE,
        NULL,
        0,
        "Thrift message Datatype",
        HFILL
      }
    },
    {
      &hf_thrift_list,
      {
        "List",
        "thrift.list",
        FT_NONE,
        BASE_NONE,
        NULL,
        0,
        "Thrift list datatype",
        HFILL
      }
    },
    {
      &hf_thrift_set,
      {
        "Set",
        "thrift.set",
        FT_NONE,
        BASE_NONE,
        NULL,
        0,
        "Thrift set datatype",
        HFILL
      }
    },
    {
      &hf_thrift_map,
      {
        "Map",
        "thrift.map",
        FT_NONE,
        BASE_NONE,
        NULL,
        0,
        "Thrift map datatype",
        HFILL
      }
    },
    {
      &hf_thrift_map_entry,
      {
        "Entry",
        "thrift.map.entry",
        FT_NONE,
        BASE_NONE,
        NULL,
        0,
        "Thrift map entry datatype",
        HFILL
      }
    }
  };

  /* setup protocol subtree arrays */
  static gint* ett[] = {
    &ett_thrift_struct,
    &ett_thrift_list,
    &ett_thrift_map,
    &ett_thrift_map_entry,
    &ett_thrift_set,
    &ett_thrift_message
  };

  /* Register protocol name and description */
  proto_thrift = proto_register_protocol("Thrift Protocol", "Thrift", "thrift");

  /* register field array */
  proto_register_field_array(proto_thrift, hf, array_length(hf));

  /* register subtree */
  proto_register_subtree_array(ett, array_length(ett));

  /* register dissector */
  register_dissector("thrift", dissect_thrift_void, proto_thrift);
}

void proto_reg_handoff_thrift(void) {
  static dissector_handle_t thrift_handle;

  heur_dissector_add("tcp", dissect_thrift, proto_thrift);
}
