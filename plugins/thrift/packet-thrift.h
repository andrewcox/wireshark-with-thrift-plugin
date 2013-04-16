extern int proto_thrift;

extern int hf_thrift_bool;
extern int hf_thrift_byte;
extern int hf_thrift_int16;
extern int hf_thrift_int32;
extern int hf_thrift_int64;
extern int hf_thrift_double;
extern int hf_thrift_string;
//extern int hf_thrift_binary;
extern int hf_thrift_struct;
extern int hf_thrift_message;
extern int hf_thrift_list;
extern int hf_thrift_map;
extern int hf_thrift_map_entry;
extern int hf_thrift_set;

extern gint ett_thrift_struct;
extern gint ett_thrift_list;
extern gint ett_thrift_map;
extern gint ett_thrift_map_entry;
extern gint ett_thrift_set;
extern gint ett_thrift_message;

gboolean try_dissect_thrift_message(tvbuff_t* tvb, packet_info* pinfo, proto_tree* parent);
