#ifndef __DESEGMENTATIONEXCEPTION_H__
#define __DESEGMENTATIONEXCEPTION_H__

extern "C" {
#include <glib.h>
}

#include <thrift/transport/TTransport.h>

class DesegmentationException : public apache::thrift::transport::TTransportException {

public:

  DesegmentationException(int pduOffset, guint32 bytesNeeded) :
    pduOffset_(pduOffset),
    bytesNeeded_(bytesNeeded) {}

  int getPduOffset() const { return pduOffset_; }
  guint32 getBytesNeeded() const { return bytesNeeded_; }

private:

  int pduOffset_;
  guint32 bytesNeeded_;

};

#endif // __DESEGMENTATIONEXCEPTION_H__
