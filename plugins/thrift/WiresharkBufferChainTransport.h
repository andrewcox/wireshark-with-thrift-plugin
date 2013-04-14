#ifndef __WIRESHARKBUFFERCHAINTRANSPORT_H__
#define __WIRESHARKBUFFERCHAINTRANSPORT_H__

extern "C" {
#include <epan/packet.h>
}

#include <thrift/transport/TTransport.h>

#include "DesegmentationException.h"

class WiresharkBufferChainTransport : public apache::thrift::transport::TTransport {

public:

  WiresharkBufferChainTransport(tvbuff_t* tvb, packet_info* pinfo) :
    offset_(0) {
    tvb_ = tvb;
    pinfo_ = pinfo;
  }

  virtual uint32_t read_virt(uint8_t* buf, uint32_t len) {

    gint length_remaining;
    length_remaining = tvb_length_remaining(tvb_, offset_);

    if (len > length_remaining) {
      len = length_remaining;
    }

    if (len <= 0) {
      throw DesegmentationException(0, DESEGMENT_ONE_MORE_SEGMENT);
    }

    const guint8* data = tvb_get_ptr(tvb_, offset_, len);
    memcpy(buf, data, len);
    offset_ += len;

    return len;

  }

  virtual uint32_t readAll_virt(uint8_t* buf, uint32_t len) {

    gint length_remaining;
    length_remaining = tvb_length_remaining(tvb_, offset_);
    if (static_cast<uint32_t>(length_remaining) < len) {
      throw DesegmentationException(0, DESEGMENT_ONE_MORE_SEGMENT);
    }

    const guint8* data = tvb_get_ptr(tvb_, offset_, len);
    memcpy(buf, data, len);
    offset_ += len;

    return len;

  }

  gint getReadOffset() {
    return offset_;
  }

  tvbuff_t* getWiresharkBuffer() {
    return tvb_;
  }

private:

  gint offset_;
  tvbuff_t* tvb_;
  packet_info* pinfo_;

};

#endif // __WIRESHARKBUFFERCHAINTRANSPORT_H__
