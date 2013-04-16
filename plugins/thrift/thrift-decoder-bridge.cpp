extern "C" {
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/emem.h>

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif
}

#undef HAVE_CONFIG_H

#include <string>
#include <sstream>
#include <limits>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <thrift/transport/TTransport.h>
#include <thrift/transport/THeaderTransport.h>
#include <thrift/protocol/THeaderProtocol.h>

#include "packet-thrift.h"
#include "DesegmentationException.h"
#include "WiresharkBufferChainTransport.h"
#include "WiresharkHeaderTransport.h"
#include "WiresharkHeaderProtocol.h"

using boost::shared_ptr;
using boost::make_shared;
using boost::dynamic_pointer_cast;

using apache::thrift::TException;
using apache::thrift::transport::TTransport;
using apache::thrift::transport::THeaderTransport;
using apache::thrift::transport::TTransportException;
using apache::thrift::protocol::TProtocol;
using apache::thrift::protocol::TMessageType;
using apache::thrift::protocol::THeaderProtocol;
using apache::thrift::protocol::TType;

using apache::thrift::protocol::T_CALL;
using apache::thrift::protocol::T_REPLY;
using apache::thrift::protocol::T_EXCEPTION;
using apache::thrift::protocol::T_ONEWAY;

std::bitset<apache::thrift::transport::CLIENT_TYPES_LEN> WiresharkHeaderTransport::clientTypes_(0xFFFFFFFF);

bool dissect_thrift_field_content(shared_ptr<WiresharkHeaderProtocol> protocol,
				  proto_tree* parent,
				  std::string fieldName,
				  TType fieldType,
				  int startOffset,
				  int16_t* pFieldId = NULL);
proto_item* dissect_thrift_struct(shared_ptr<WiresharkHeaderProtocol> protocol, proto_tree* parent, TMessageType messageType = (TMessageType)0, int16_t* pFieldId = NULL);
proto_item* dissect_thrift_list(shared_ptr<WiresharkHeaderProtocol> protocol, proto_tree* parent, int16_t* pFieldId = NULL);
proto_item* dissect_thrift_set(shared_ptr<WiresharkHeaderProtocol> protocol, proto_tree* parent, int16_t* pFieldId = NULL);
proto_item* dissect_thrift_map(shared_ptr<WiresharkHeaderProtocol> protocol, proto_tree* parent, int16_t* pFieldId = NULL);

const char* field_id_to_text(int16_t* pFieldId) {
  std::stringstream s;

  if (pFieldId == NULL) {
    s << "";
  } else {
    s << (*pFieldId) << ": ";
  }

  return s.str().c_str();
}

class ThriftDissector {

public:

  static std::string clientTypeToString(apache::thrift::transport::CLIENT_TYPE clientType) {

    std::string clientTypeName;

    switch (clientType) {

    case apache::thrift::transport::THRIFT_HEADER_CLIENT_TYPE:
      clientTypeName = "header";
      break;

    case apache::thrift::transport::THRIFT_FRAMED_DEPRECATED:
      clientTypeName = "framed";
      break;

    case apache::thrift::transport::THRIFT_UNFRAMED_DEPRECATED:
      clientTypeName = "unframed";
      break;

    case apache::thrift::transport::THRIFT_HTTP_CLIENT_TYPE:
      clientTypeName = "http";
      break;

    default:
      clientTypeName = "<unknown>";
      break;

    }

    return clientTypeName;
  }

  static std::string messageTypeToString(apache::thrift::protocol::TMessageType messageType) {
    std::string messageTypeName;

    switch (messageType) {

    case T_CALL:
      messageTypeName = "call";
      break;

    case T_REPLY:
      messageTypeName = "reply";
      break;

    case T_EXCEPTION:
      messageTypeName = "exception";
      break;

    case T_ONEWAY:
      messageTypeName = "oneway";
      break;

    default:
      messageTypeName = "<unknown>";
      break;

    }

    return messageTypeName;
  }

};

bool dissect_thrift_field_content(shared_ptr<WiresharkHeaderProtocol> protocol,
				  proto_tree* parent,
				  std::string fieldName,
				  TType fieldType,
				  int startOffset,
				  int16_t* pFieldId)
{
  std::map<TType, const char*> fieldTypeName;

  fieldTypeName[apache::thrift::protocol::T_BOOL] = "bool";
  fieldTypeName[apache::thrift::protocol::T_BYTE] = "byte";
  fieldTypeName[apache::thrift::protocol::T_I16] = "i16";
  fieldTypeName[apache::thrift::protocol::T_I32] = "i32";
  fieldTypeName[apache::thrift::protocol::T_I64] = "i64";
  fieldTypeName[apache::thrift::protocol::T_DOUBLE] = "double";
  fieldTypeName[apache::thrift::protocol::T_STRING] = "string";
  fieldTypeName[apache::thrift::protocol::T_STRUCT] = "struct";
  fieldTypeName[apache::thrift::protocol::T_MAP] = "map";
  fieldTypeName[apache::thrift::protocol::T_SET] = "set";
  fieldTypeName[apache::thrift::protocol::T_LIST] = "list";

  switch (fieldType) {

  case apache::thrift::protocol::T_BOOL:
    {
    bool boolValue;
    protocol->readBool(boolValue);
    proto_item* ti = proto_tree_add_item(parent,
					 hf_thrift_bool,
					 protocol->getWiresharkBuffer(),
					 startOffset,
					 protocol->getReadOffset() - startOffset,
					 FALSE);
    proto_item_set_text(ti,
			"%s%s: %s",
			field_id_to_text(pFieldId),
			fieldTypeName[fieldType],
			boolValue ? "true" : "false");
    break;
    }

  case apache::thrift::protocol::T_BYTE:
    {
    int8_t byteValue;
    protocol->readByte(byteValue);
    proto_item* ti = proto_tree_add_item(parent,
					 hf_thrift_byte,
					 protocol->getWiresharkBuffer(),
					 startOffset,
					 protocol->getReadOffset() - startOffset,
					 FALSE);
    proto_item_set_text(ti,
			"%s%s: %d",
			field_id_to_text(pFieldId),
			fieldTypeName[fieldType],
			byteValue);
    break;
    }

  case apache::thrift::protocol::T_I16:
    {
    int16_t shortValue;
    protocol->readI16(shortValue);
    proto_item* ti = proto_tree_add_item(parent,
					 hf_thrift_int16,
					 protocol->getWiresharkBuffer(),
					 startOffset,
					 protocol->getReadOffset() - startOffset,
					 FALSE);
    proto_item_set_text(ti,
			"%s%s: %d",
			field_id_to_text(pFieldId),
			fieldTypeName[fieldType],
			shortValue);
    break;
    }

  case apache::thrift::protocol::T_I32:
    {
    int32_t integerValue;
    protocol->readI32(integerValue);
    proto_item* ti = proto_tree_add_item(parent,
					 hf_thrift_int32,
					 protocol->getWiresharkBuffer(),
					 startOffset,
					 protocol->getReadOffset() - startOffset,
					 FALSE);
    proto_item_set_text(ti,
			"%s%s: %d",
			field_id_to_text(pFieldId),
			fieldTypeName[fieldType],
			integerValue);
    break;
    }

  case apache::thrift::protocol::T_DOUBLE:
    {
    double doubleValue;
    protocol->readDouble(doubleValue);
    proto_item* ti = proto_tree_add_item(parent,
					 hf_thrift_double,
					 protocol->getWiresharkBuffer(),
					 startOffset,
					 protocol->getReadOffset() - startOffset,
					 FALSE);
    proto_item_set_text(ti,
			"%s%s: %lf",
			field_id_to_text(pFieldId),
			fieldTypeName[fieldType],
			doubleValue);
    break;
    }

  case apache::thrift::protocol::T_STRING:
    {
    std::string stringValue;
    protocol->readString(stringValue);
    proto_item* ti = proto_tree_add_item(parent,
					 hf_thrift_string,
					 protocol->getWiresharkBuffer(),
					 startOffset,
					 protocol->getReadOffset() - startOffset,
					 FALSE);
    proto_item_set_text(ti,
			"%s%s: \"%s\"",
			field_id_to_text(pFieldId),
			fieldTypeName[fieldType],
			stringValue.c_str());
    break;
    }

  case apache::thrift::protocol::T_STRUCT:
    dissect_thrift_struct(protocol, parent, (TMessageType)0, pFieldId);
    break;

  case apache::thrift::protocol::T_MAP:
    dissect_thrift_map(protocol, parent, pFieldId);
    break;

  case apache::thrift::protocol::T_LIST:
    dissect_thrift_list(protocol, parent, pFieldId);
    break;

  case apache::thrift::protocol::T_SET:
    dissect_thrift_set(protocol, parent, pFieldId);
    break;

  case apache::thrift::protocol::T_I64:
    {
    int64_t longLongValue;
    protocol->readI64(longLongValue);
    proto_item* ti = proto_tree_add_item(parent,
					 hf_thrift_double,
					 protocol->getWiresharkBuffer(),
					 startOffset,
					 protocol->getReadOffset() - startOffset,
					 FALSE);
    proto_item_set_text(ti,
			"%s%s: %lld",
			field_id_to_text(pFieldId),
			fieldTypeName[fieldType],
			longLongValue);
    break;
    }

  case apache::thrift::protocol::T_UTF8:
  case apache::thrift::protocol::T_UTF16:
  case apache::thrift::protocol::T_U64:
  case apache::thrift::protocol::T_VOID:
    {
    protocol->skip(fieldType);
    proto_item* ti = proto_tree_add_item(parent,
					 hf_thrift_unknown,
					 protocol->getWiresharkBuffer(),
					 startOffset,
					 protocol->getReadOffset() - startOffset,
					 FALSE);
    proto_item_set_text(ti,
			"%s: <unhandled field type>",
			field_id_to_text(pFieldId));
    break;
    }

  case apache::thrift::protocol::T_STOP:
    // end of struct
    return false;
  }

  return true;
}

bool dissect_thrift_field(shared_ptr<WiresharkHeaderProtocol> protocol, proto_tree* parent)
{
  std::string fieldName;
  TType fieldType;
  int16_t fieldId;

  gint dataStartOffset = protocol->getReadOffset();
  protocol->readFieldBegin(fieldName, fieldType, fieldId);
  bool ret = dissect_thrift_field_content(protocol, parent, fieldName, fieldType, dataStartOffset, &fieldId);
  protocol->readFieldEnd();
  return ret;
}

proto_item* dissect_thrift_list(shared_ptr<WiresharkHeaderProtocol> protocol, proto_tree* parent, int16_t *pFieldId)
{
  if (parent == NULL) {
    protocol->skip(apache::thrift::protocol::T_LIST);
    return NULL;
  }

  int listStartOffset;
  int startOffset;

  listStartOffset = protocol->getReadOffset();
  proto_item* ti = proto_tree_add_item(parent,
  				       hf_thrift_list,
  				       protocol->getWiresharkBuffer(),
  				       listStartOffset,
  				       -1,
  				       FALSE);
  proto_tree* subtree = proto_item_add_subtree(ti,
  					       ett_thrift_list);

  TType elemType;
  uint32_t size;
  protocol->readListBegin(elemType, size);

  for (int i = 0; i < size; i++) {
    startOffset = protocol->getReadOffset();
    if (!dissect_thrift_field_content(protocol, subtree, "", elemType, startOffset)) {
      return NULL;
    }
  }

  protocol->readListEnd();

  proto_item_set_len(ti, protocol->getReadOffset() - listStartOffset);
}

proto_item* dissect_thrift_set(shared_ptr<WiresharkHeaderProtocol> protocol, proto_tree* parent, int16_t *pFieldId)
{
  if (parent == NULL) {
    protocol->skip(apache::thrift::protocol::T_SET);
    return NULL;
  }

  int setStartOffset;
  int startOffset;

  setStartOffset = protocol->getReadOffset();
  proto_item* ti = proto_tree_add_item(parent,
  				       hf_thrift_set,
  				       protocol->getWiresharkBuffer(),
  				       setStartOffset,
  				       -1,
  				       FALSE);
  proto_tree* subtree = proto_item_add_subtree(ti,
  					       ett_thrift_set);

  TType elemType;
  uint32_t size;
  protocol->readSetBegin(elemType, size);

  for (int i = 0; i < size; i++) {
    startOffset = protocol->getReadOffset();
    if (!dissect_thrift_field_content(protocol, subtree, "", elemType, startOffset)) {
      return NULL;
    }
  }

  protocol->readSetEnd();

  proto_item_set_len(ti, protocol->getReadOffset() - setStartOffset);
}

proto_item* dissect_thrift_map(shared_ptr<WiresharkHeaderProtocol> protocol, proto_tree* parent, int16_t* pFieldId)
{
  if (parent == NULL) {
    protocol->skip(apache::thrift::protocol::T_MAP);
    return NULL;
  }

  int startOffset;
  int mapStartOffset;

  mapStartOffset = protocol->getReadOffset();
  proto_item* mapItem = proto_tree_add_item(parent,
  				       hf_thrift_map,
  				       protocol->getWiresharkBuffer(),
  				       mapStartOffset,
  				       -1,
  				       FALSE);
  proto_tree* mapSubtree = proto_item_add_subtree(mapItem,
  					       ett_thrift_map);

  TType keyType;
  TType valType;
  uint32_t size;
  protocol->readMapBegin(keyType, valType, size);

  for (int i = 0; i < size; i++) {
    int mapEntryStartOffset = protocol->getReadOffset();
    proto_item* ti = proto_tree_add_item(mapSubtree,
                                         hf_thrift_map_entry,
                                         protocol->getWiresharkBuffer(),
                                         mapEntryStartOffset,
                                         -1,
                                         FALSE);
    proto_tree* subtree = proto_item_add_subtree(ti,
                                                 ett_thrift_map_entry);

    startOffset = protocol->getReadOffset();
    if (!dissect_thrift_field_content(protocol, subtree, "key: ", keyType, startOffset)) {
      return NULL;
    }
    startOffset = protocol->getReadOffset();
    if (!dissect_thrift_field_content(protocol, subtree, "value: ", valType, startOffset)) {
      return NULL;
    }

    proto_item_set_len(ti, protocol->getReadOffset() - mapEntryStartOffset);
  }

  protocol->readMapEnd();

  proto_item_set_len(mapItem, protocol->getReadOffset() - mapStartOffset);

  return mapItem;
}

proto_item* dissect_thrift_struct(shared_ptr<WiresharkHeaderProtocol> protocol, proto_tree* parent, TMessageType messageType, int16_t* pFieldId)
{
  if (parent == NULL) {
    protocol->skip(apache::thrift::protocol::T_STRUCT);
    return NULL;
  }

  std::string structName;

  gint startOffset = protocol->getReadOffset();
  proto_item* ti = proto_tree_add_item(parent,
  				       hf_thrift_struct,
  				       protocol->getWiresharkBuffer(),
  				       startOffset,
  				       -1,
  				       FALSE);
  proto_tree* subtree = proto_item_add_subtree(ti,
  					       ett_thrift_struct);

  protocol->readStructBegin(structName);
  while (true)
  {
    if (!dissect_thrift_field(protocol, subtree)) {
      break;
    }
  }
  protocol->readStructEnd();

  if (messageType != 0) {
    switch (messageType) {
    case T_CALL:
    case T_ONEWAY:
      proto_item_set_text(ti, "call arguments");
      break;
    case T_REPLY:
      proto_item_set_text(ti, "return values");
      break;
    case T_EXCEPTION:
      proto_item_set_text(ti, "exception");
      break;
    }
  } else if (pFieldId == NULL) {
    proto_item_set_text(ti, "struct");
  } else {
    proto_item_set_text(ti, "%sstruct", field_id_to_text(pFieldId));
  }

  proto_item_set_len(ti, protocol->getReadOffset() - startOffset);

  return ti;
}

proto_item* dissect_thrift_exception(shared_ptr<WiresharkHeaderProtocol> protocol, proto_tree* parent)
{
  proto_item* item = dissect_thrift_struct(protocol, parent, T_EXCEPTION);
  if (NULL != item) {
    proto_item_set_text(item, "exception");
  }
  return item;
}

void dissect_thrift_message_data(shared_ptr<WiresharkHeaderProtocol> protocol,
				 TMessageType messageType,
				 proto_tree* parent)
{
    switch (messageType) {

    case T_CALL:
    case T_ONEWAY:
    case T_REPLY:

      // Two-way calls, one-way calls, and replies all represent the payload
      // (arguments or return values) as a Thrift struct.

      dissect_thrift_struct(protocol, parent, messageType);
      break;

    case T_EXCEPTION:

      dissect_thrift_exception(protocol, parent);
      break;

    default:
      throw new TTransportException("Unrecognized message type");
      break;

    }
}

void setColumnText(packet_info* pinfo, const gint columnId, const std::string& text)
{
  if (check_col(pinfo->cinfo, columnId)) {
    col_set_str(pinfo->cinfo, columnId, se_strdup(text.c_str()));
  }
}

gboolean try_dissect_thrift_message(tvbuff_t* tvb, packet_info* pinfo, proto_tree* parent)
{
  gint messageOffset;

  shared_ptr<WiresharkBufferChainTransport> transport =
    make_shared<WiresharkBufferChainTransport>(tvb, pinfo);

  shared_ptr<WiresharkHeaderTransport> headerTransport =
    make_shared<WiresharkHeaderTransport>(transport);

  shared_ptr<WiresharkHeaderProtocol> protocol =
    make_shared<WiresharkHeaderProtocol>(headerTransport);

  std::string methodName;
  TMessageType messageType;
  int sequenceId;

  try {

    proto_item* tree_item = NULL;
    proto_tree* subtree = NULL;

    protocol->readMessageBegin(methodName, messageType, sequenceId);
    messageOffset = protocol->getThriftMessageBegin();
    if (protocol->getIsFramed()) {
      messageOffset += 4;
    }

    if (parent) {

      std::stringstream info;
      info << "clienttype=" << ThriftDissector::clientTypeToString(protocol->getClientType())
	   << " msgtype=" << ThriftDissector::messageTypeToString(messageType)
	   << " method=" << methodName << "()"
	   << " sequence=" << sequenceId;

      setColumnText(pinfo, COL_PROTOCOL, "Thrift");
      setColumnText(pinfo, COL_INFO, info.str());
      setColumnText(pinfo, COL_IF_DIR, ((messageType == T_CALL) ? "IN" : "OUT"));

      // Add a Thrift protocol item to the packet dissection. This is what
      // enables the "thrift" display filter to work (to show only Thrift
      // packets).
      tree_item = proto_tree_add_item(parent,
				      proto_thrift,
				      protocol->getWiresharkBuffer(),
				      messageOffset,
				      -1,
				      FALSE);

      // Make the Thrift protocol item a subtree
      subtree = proto_item_add_subtree(tree_item,
				       ett_thrift_message);
    }

    dissect_thrift_message_data(protocol, messageType, subtree);
    protocol->readMessageEnd();

    if (NULL != tree_item) {
      proto_item_set_len(tree_item, protocol->getReadOffset() - messageOffset);
    }

  } catch (const DesegmentationException& ex) {

    // Exception was thrown indicating not enough data was left in the TCP
    // conversation. Handle this by telling wireshark we need more data. It
    // will call us back next time with everything we saw this time, plus an
    // extra packet's worth.

    pinfo->desegment_offset = ex.getPduOffset();
    pinfo->desegment_len = ex.getBytesNeeded();

    return TRUE;

  } catch (...) {

    // In case of a failure to dissect the stream for any other reason,
    // either it isn't a Thrift message, or it isn't understood by this
    // dissector.

    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

    return FALSE;

  }

  // Everything went according to plan.

  return TRUE;
}
