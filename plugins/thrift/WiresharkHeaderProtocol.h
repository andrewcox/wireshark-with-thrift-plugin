#ifndef __WIRESHARKHEADERPROTOCOL_H__
#define __WIRESHARKHEADERPROTOCOL_H__

#include <epan/packet.h>
#include <thrift/transport/THeaderTransport.h>
#include <thrift/protocol/THeaderProtocol.h>
#include <thrift/protocol/TVirtualProtocol.h>

class WiresharkHeaderProtocol
    : public apache::thrift::protocol::TVirtualProtocol<WiresharkHeaderProtocol, apache::thrift::protocol::THeaderProtocol> {

public:

  WiresharkHeaderProtocol(boost::shared_ptr<apache::thrift::transport::TTransport> transport,
                          std::bitset<CLIENT_TYPES_LEN>* clientTypes = NULL)
    : apache::thrift::protocol::TVirtualProtocol<WiresharkHeaderProtocol, apache::thrift::protocol::THeaderProtocol>(getTransportWrapper(transport,
                                                                                                                                         clientTypes))
  {
  }

  boost::shared_ptr<WiresharkHeaderTransport> getWiresharkHeaderTransport() {
    boost::shared_ptr<WiresharkHeaderTransport> headerTransport =
      boost::dynamic_pointer_cast<WiresharkHeaderTransport, apache::thrift::transport::TTransport>(getTransport());
    return headerTransport;
  }

  boost::shared_ptr<WiresharkBufferChainTransport> getWiresharkBufferTransport() {
    return getWiresharkHeaderTransport()->getUnderlyingTransport();
  }

  ::gint getThriftMessageBegin() {
    return getWiresharkHeaderTransport()->getThriftMessageBegin();
  }

  ::gint getReadOffset() {
    return getWiresharkHeaderTransport()->getReadOffset();
  }

  ::tvbuff_t* getWiresharkBuffer() {
    return getWiresharkBufferTransport()->getWiresharkBuffer();
  }

  apache::thrift::transport::CLIENT_TYPE getClientType() {
    return getWiresharkHeaderTransport()->getClientType();
  }

  bool getIsFramed() {
    return getWiresharkHeaderTransport()->getIsFramed();
  }

};

#endif // __WIRESHARKHEADERPROTOCOL_H__
