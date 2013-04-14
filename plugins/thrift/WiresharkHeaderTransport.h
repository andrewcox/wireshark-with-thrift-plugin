#ifndef __WIRESHARKINPUTTRANPORT_H__
#define __WIRESHARKINPUTTRANPORT_H__

#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>

#include <thrift/transport/THeaderTransport.h>
#include <thrift/transport/TVirtualTransport.h>

class WiresharkHeaderTransport
: public apache::thrift::transport::TVirtualTransport<WiresharkHeaderTransport, apache::thrift::transport::THeaderTransport> {

  typedef apache::thrift::transport::TVirtualTransport<WiresharkHeaderTransport, apache::thrift::transport::THeaderTransport> VirtualBase;

public:

  WiresharkHeaderTransport(boost::shared_ptr<WiresharkBufferChainTransport> transport)
  //    : THeaderTransport(transport, &clientTypes_)
  {
    initSupportedClients(&clientTypes_);
    clientType = apache::thrift::transport::THRIFT_UNFRAMED_DEPRECATED;

    transport_ = transport;
    httpTransport_ = transport;

    readPos_ = 0;
  }

  apache::thrift::transport::CLIENT_TYPE getClientType() const {
    return static_cast<CLIENT_TYPE>(clientType);
  }

  boost::shared_ptr<WiresharkBufferChainTransport> getUnderlyingTransport() {
    return boost::dynamic_pointer_cast<WiresharkBufferChainTransport, TTransport>(apache::thrift::transport::THeaderTransport::getUnderlyingTransport());
    //return boost::dynamic_pointer_cast<WiresharkBufferChainTransport, TTransport>(transport_);
  }

  bool getIsFramed() {
    apache::thrift::transport::CLIENT_TYPE clientType = getClientType();
    return
      (clientType != apache::thrift::transport::THRIFT_UNFRAMED_DEPRECATED) &&
      (clientType != apache::thrift::transport::THRIFT_HTTP_CLIENT_TYPE);
  }

  gint getReadOffset() {
    if (getClientType() == apache::thrift::transport::THRIFT_HTTP_CLIENT_TYPE) {
      return boost::dynamic_pointer_cast<apache::thrift::transport::THttpTransport, apache::thrift::transport::TTransport>(httpTransport_)->getBytesConsumed();
    }

    return (rBase_ - rBuf_.get()) + (getIsFramed() ? 4 : 0);
  }

  gint getThriftMessageBegin() {
    if (getClientType() == apache::thrift::transport::THRIFT_HTTP_CLIENT_TYPE) {
      return boost::dynamic_pointer_cast<apache::thrift::transport::THttpTransport, apache::thrift::transport::TTransport>(httpTransport_)->getContentBegin();
    }

    return (getIsFramed() ? 4 : 0);
  }

  /* uint32_t read(uint8_t* buf, uint32_t len) { */
  /*   return getUnderlyingTransport()->read(buf, len); */
  /* } */

  /* uint32_t readAll(uint8_t* buf, uint32_t len) { */
  /*   return getUnderlyingTransport()->readAll(buf, len); */
  /* } */

  uint32_t readAll(uint8_t* buf, uint32_t len) {
    readPos_ += len;
    return this->VirtualBase::readAll(buf, len);
  }

private:

  static std::bitset<CLIENT_TYPES_LEN> clientTypes_;
  int readPos_;
};

#endif // __WIRESHARKINPUTTRANPORT_H__
