#include "extensions/filters/listener/tls_inspector/tls_inspector.h"

#include <arpa/inet.h>

#include <cstdint>
#include <string>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/event/dispatcher.h"
#include "envoy/network/listen_socket.h"
#include "envoy/stats/scope.h"

#include "common/api/os_sys_calls_impl.h"
#include "common/common/assert.h"

#include "extensions/filters/listener/tls_inspector/openssl_impl.h"
#include "extensions/transport_sockets/well_known_names.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace TlsInspector {

Config::Config(Stats::Scope& scope, uint32_t max_client_hello_size)
    : stats_{ALL_TLS_INSPECTOR_STATS(POOL_COUNTER_PREFIX(scope, "tls_inspector."))},
      ssl_ctx_(
          SSL_CTX_new(Envoy::Extensions::ListenerFilters::TlsInspector::TLS_with_buffers_method())),
      max_client_hello_size_(max_client_hello_size) {
std::cerr << "!!!!!!!!!!!!!!!!! Config::Config \n";
  if (max_client_hello_size_ > TLS_MAX_CLIENT_HELLO) {
    throw EnvoyException(fmt::format("max_client_hello_size of {} is greater than maximum of {}.",
                                     max_client_hello_size_, size_t(TLS_MAX_CLIENT_HELLO)));
  }

  SSL_CTX_set_options(ssl_ctx_.get(), SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(ssl_ctx_.get(), SSL_SESS_CACHE_OFF);

  Envoy::Extensions::ListenerFilters::TlsInspector::set_certificate_cb(ssl_ctx_.get());

  auto tlsext_servername_cb = +[](SSL* ssl, int* out_alert, void* arg) -> int {
std::cerr << "!!!!!!!!!!!!!!!!!!!! servername_cb \n";	  
    Filter* filter = static_cast<Filter*>(SSL_get_app_data(ssl));
    absl::string_view servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    filter->onCert();
    filter->onServername(servername);

    return Envoy::Extensions::ListenerFilters::TlsInspector::getServernameCallbackReturn(out_alert);
  };
  SSL_CTX_set_tlsext_servername_callback(ssl_ctx_.get(), tlsext_servername_cb);

  auto alpn_cb = [](SSL* ssl, const unsigned char** out, unsigned char* outlen,
                    const unsigned char* in, unsigned int inlen, void* arg) -> int {
std::cerr << "!!!!!!!!!!!!!!!!!!!! alpn_cb \n";
    Filter* filter = static_cast<Filter*>(SSL_get_app_data(ssl));
    filter->onALPN(in, inlen);

    return SSL_TLSEXT_ERR_OK;
  };
  SSL_CTX_set_alpn_select_cb(ssl_ctx_.get(), alpn_cb, nullptr);

  auto cert_cb = [](SSL* ssl, void* arg) -> int {
std::cerr << "!!!!!!!!!!!!!!!!!!!! cert_cb \n";	  
//    Filter* filter = static_cast<Filter*>(SSL_get_app_data(ssl));
//    filter->onCert();    

    return SSL_TLSEXT_ERR_OK;
  };
  SSL_CTX_set_cert_cb(ssl_ctx_.get(), cert_cb, nullptr);

}

bssl::UniquePtr<SSL> Config::newSsl() { return bssl::UniquePtr<SSL>{SSL_new(ssl_ctx_.get())}; }

thread_local uint8_t Filter::buf_[Config::TLS_MAX_CLIENT_HELLO];

Filter::Filter(const ConfigSharedPtr config) : config_(config), ssl_(config_->newSsl()) {
  RELEASE_ASSERT(sizeof(buf_) >= config_->maxClientHelloSize(), "");

  SSL_set_app_data(ssl_.get(), this);
  SSL_set_accept_state(ssl_.get());
}

Network::FilterStatus Filter::onAccept(Network::ListenerFilterCallbacks& cb) {
std::cerr << "!!!!!!!!!!!!!!!! tls_inspector onAccept \n";
  ENVOY_LOG(debug, "tls inspector: new connection accepted");
  Network::ConnectionSocket& socket = cb.socket();
  ASSERT(file_event_ == nullptr);

  file_event_ = cb.dispatcher().createFileEvent(
	  socket.ioHandle().fd(),
      [this](uint32_t events) {
        if (events & Event::FileReadyType::Closed) {
          config_->stats().connection_closed_.inc();
          done(false);
          return;
        }

        ASSERT(events == Event::FileReadyType::Read);
        onRead();
      },
      Event::FileTriggerType::Edge, Event::FileReadyType::Read | Event::FileReadyType::Closed);

  cb_ = &cb;
  return Network::FilterStatus::StopIteration;
}

void Filter::onALPN(const unsigned char* data, unsigned int len) {
std::cerr << "!!!!!!!!!!!!!!!! tls_inspector onALPN \n";
  std::vector<absl::string_view> protocols =
      Envoy::Extensions::ListenerFilters::TlsInspector::getAlpnProtocols(data, len);
  cb_->socket().setRequestedApplicationProtocols(protocols);
  alpn_found_ = true;
}

void Filter::onCert() {
  std::cerr << "!!!!!!!!!!!!!!!!!!!! tls_inspector onCert \n";
std::cerr << "!!!!!!!!!!!!!!!!!! calling cb_->socket().setRequestedApplicationProtocols alpn_found_ \n"; 
  std::vector<absl::string_view> protocols;
  protocols.emplace_back("istio");
//  unsigned char protos[] = {
//     5, 'i', 's', 't', 'i', 'o'
//  };
//  unsigned int num_protos = sizeof(protos);  
//  protocols.emplace_back(reinterpret_cast<const char*>(protos), 6);
  cb_->socket().setRequestedApplicationProtocols(protocols);
//  alpn_found_ = true;
}

void Filter::onServername(absl::string_view name) {
std::cerr << "!!!!!!!!!!!!!!!! tls_inspector onServername !! " << name << " \n";	
  if (!name.empty()) {
    config_->stats().sni_found_.inc();
    cb_->socket().setRequestedServerName(name);
    ENVOY_LOG(debug, "tls:onServerName(), requestedServerName: {}", name);
  } else {
    config_->stats().sni_not_found_.inc();
  }
  clienthello_success_ = true;
//  std::vector<absl::string_view> protocols;
//  protocols.at(0) = "istio";
//  cb_->socket().setRequestedApplicationProtocols(protocols);

//  const unsigned char *alpn = NULL;
//  unsigned int alpnlen = 0;
//  std::cerr << "!!!!!!!!!!!!!!!! calling SSL_get0_next_proto_negotiated \n";
//  SSL_get0_next_proto_negotiated(ssl_.get(), &alpn, &alpnlen);
//std::cerr << "!!!!!!!!!!!!!!!! called SSL_get0_next_proto_negotiated " << alpn << " \n";
//  if (alpn == NULL) {
//    std::cerr << "!!!!!!!!!!!!!!!!!! calling SSL_get0_alpn_selected \n";
//    SSL_get0_alpn_selected(ssl_.get(), &alpn, &alpnlen);
//std::cerr << "!!!!!!!!!!!!!!!!!! SSL_get0_alpn_selected " << alpn << " " << alpnlen << " \n";
//  }
  
}

void Filter::onRead() {
std::cerr << "!!!!!!!!!!!!!!!! tls_inspector onRead \n";
	
  // This receive code is somewhat complicated, because it must be done as a MSG_PEEK because
  // there is no way for a listener-filter to pass payload data to the ConnectionImpl and filters
  // that get created later.
  //
  // The file_event_ in this class gets events everytime new data is available on the socket,
  // even if previous data has not been read, which is always the case due to MSG_PEEK. When
  // the TlsInspector completes and passes the socket along, a new FileEvent is created for the
  // socket, so that new event is immediately signalled as readable because it is new and the socket
  // is readable, even though no new events have occurred.
  //
  // TODO(ggreenway): write an integration test to ensure the events work as expected on all
  // platforms.
  auto& os_syscalls = Api::OsSysCallsSingleton::get();
  const Api::SysCallSizeResult result = os_syscalls.recv(cb_->socket().ioHandle().fd(), buf_,
                                                         config_->maxClientHelloSize(), MSG_PEEK);
  ENVOY_LOG(trace, "tls inspector: recv: {}", result.rc_);

  if (result.rc_ == -1 && result.errno_ == EAGAIN) {
    return;
  } else if (result.rc_ < 0) {
    config_->stats().read_error_.inc();
    done(false);
    return;
  }

  // Because we're doing a MSG_PEEK, data we've seen before gets returned every time, so
  // skip over what we've already processed.
  if (static_cast<uint64_t>(result.rc_) > read_) {
    const uint8_t* data = buf_ + read_;
    const size_t len = result.rc_ - read_;
    read_ = result.rc_;
    parseClientHello(data, len);
  }
}

void Filter::done(bool success) {
std::cerr << "!!!!!!!!!!!!!!!! tls_inspector done \n";	
  ENVOY_LOG(trace, "tls inspector: done: {}", success);
  file_event_.reset();
  cb_->continueFilterChain(success); 
}

void Filter::parseClientHello(const void* data, size_t len) {
std::cerr << "!!!!!!!!!!!!!!!! tls_inspector parseClientHello \n";	
  // Ownership is passed to ssl_ in SSL_set_bio()
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(data, len));

  // Make the mem-BIO return that there is more data
  // available beyond it's end
  BIO_set_mem_eof_return(bio.get(), -1);

  SSL_set_bio(ssl_.get(), bio.get(), bio.get());
  bio.release();

  int ret = SSL_do_handshake(ssl_.get());

  // This should never succeed because an error is always returned from the SNI callback.
  ASSERT(ret <= 0);
  switch (SSL_get_error(ssl_.get(), ret)) {
  case SSL_ERROR_WANT_READ:
std::cerr << "!!!!!!!!!!!!!! SSL_ERROR_WANT_READ \n";
    if (read_ == config_->maxClientHelloSize()) {
      // We've hit the specified size limit. This is an unreasonably large ClientHello;
      // indicate failure.
      config_->stats().client_hello_too_large_.inc();
      done(false);
    }
    break;
  case SSL_ERROR_SSL:
std::cerr << "!!!!!!!!!!!!!! SSL_ERROR_SSL " << clienthello_success_ << " \n";    
    if (clienthello_success_) {
      config_->stats().tls_found_.inc();
      if (alpn_found_) {
        config_->stats().alpn_found_.inc();
      } else {
        config_->stats().alpn_not_found_.inc();
      }
std::cerr << "!!!!!!!!!!!!!!!!!!!! setDetectedTransportProtocol Tls \n";      
      cb_->socket().setDetectedTransportProtocol(TransportSockets::TransportSocketNames::get().Tls);
    } else {
      config_->stats().tls_not_found_.inc();
    }
    done(true);
    break;
  default:
std::cerr << "!!!!!!!!!!!!!!!!!!!! default err \n";    
    done(false);
    break;
  }
}

} // namespace TlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
