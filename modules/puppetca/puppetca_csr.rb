module Proxy::PuppetCa
  class CertificateRequest
    attr_reader :csr

    def initialize(raw_csr)
      @csr = OpenSSL::X509::Request.new(raw_csr)
      #rescue OpenSSL::X509::RequestError => e
      #Foreman::Logging.exception('Could not load CSR: ', e)
    end

    delegate :subject, to: :csr

    def cn
      subject.to_s[/CN=([^\s\/,]+)/i, 1]
    end

    def challenge_password
      custom_attributes.detect do |attr|
        ['challengePassword', '1.2.840.113549.1.9.7'].include?(attr[:oid])
      end.try(:[], :value)
    end

    def custom_attributes
      @csr.attributes.map do |attr|
        {
          oid: attr.oid,
          value: attr.value.value.first.value
        }
      end
    end
  end
end
