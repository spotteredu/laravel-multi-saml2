<?php

namespace Spotter\Saml2\Http\Middleware;

use Closure;
use OneLogin_Saml2_Auth;
use Spotter\Saml2\Contracts\IdpResolver;

class SubdomainBindSaml
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {
        $subdomain = $request->subdomain;
        $idpSettings = call_user_func([$idpResolver, 'idpSettings'], $subdomain);
        $spSettings = $this->getBaseSettings();

        $settings = array_merge($spSettings, [ 'idp' => $idpSettings ]);
        $this->app->saml2Auth =  new OneLogin_Saml2_Auth($settings);

        return $next($request);
    }

    protected function getIdpResolver() {
        $idpResolver = Config::get('saml2.idpResolver');
        if (is_subclass_of($idpResolver, IdpResolver::class)) {
            return $idpResolver;
        }
        throw new \Exception('Invalid IdpResolver implementation');
    }

    protected function getBaseSettings() {
        $config = config('saml2');
        if (empty($config['sp']['entityId'])) {
            $config['sp']['entityId'] = URL::route('saml_metadata');
        }
        if (empty($config['sp']['assertionConsumerService']['url'])) {
            $config['sp']['assertionConsumerService']['url'] = URL::route('saml_acs');
        }
        if (!empty($config['sp']['singleLogoutService']) &&
            empty($config['sp']['singleLogoutService']['url'])) {
            $config['sp']['singleLogoutService']['url'] = URL::route('saml_sls');
        }
        if (strpos($config['sp']['privateKey'], 'file://')===0) {
            $config['sp']['privateKey'] = $this->extractPkeyFromFile($config['sp']['privateKey']);
        }
        if (strpos($config['sp']['x509cert'], 'file://')===0) {
            $config['sp']['x509cert'] = $this->extractCertFromFile($config['sp']['x509cert']);
        }
        return $config;
    }

    protected function extractPkeyFromFile($path) {
        $res = openssl_get_privatekey($path);
        if (empty($res)) {
            throw new \Exception('Could not read private key-file at path \'' . $path . '\'');
        }
        openssl_pkey_export($res, $pkey);
        openssl_pkey_free($res);
        return $this->extractOpensslString($pkey, 'PRIVATE KEY');
    }

    protected function extractCertFromFile($path) {
        $res = openssl_x509_read(file_get_contents($path));
        if (empty($res)) {
            throw new \Exception('Could not read X509 certificate-file at path \'' . $path . '\'');
        }
        openssl_x509_export($res, $cert);
        openssl_x509_free($res);
        return $this->extractOpensslString($cert, 'CERTIFICATE');
    }

    protected function extractOpensslString($keyString, $delimiter) {
        $keyString = str_replace(["\r", "\n"], "", $keyString);
        $regex = '/-{5}BEGIN(?:\s|\w)+' . $delimiter . '-{5}\s*(.+?)\s*-{5}END(?:\s|\w)+' . $delimiter . '-{5}/m';
        preg_match($regex, $keyString, $matches);
        return empty($matches[1]) ? '' : $matches[1];
    }




    // // Identity Provider Data that we want connect with our SP
    // 'idp' => array(
    //     // Identifier of the IdP entity  (must be a URI)
    //     'entityId' => env('SAML2_IDP_ENTITYID', $idp_host . '/saml2/idp/metadata.php'),
    //     // SSO endpoint info of the IdP. (Authentication Request protocol)
    //     'singleSignOnService' => array(
    //         // URL Target of the IdP where the SP will send the Authentication Request Message,
    //         // using HTTP-Redirect binding.
    //         'url' => $idp_host . '/saml2/idp/SSOService.php',
    //     ),
    //     // SLO endpoint info of the IdP.
    //     'singleLogoutService' => array(
    //         // URL Location of the IdP where the SP will send the SLO Request,
    //         // using HTTP-Redirect binding.
    //         'url' => $idp_host . '/saml2/idp/SingleLogoutService.php',
    //     ),
    //     // Public x509 certificate of the IdP
    //     'x509cert' => env('SAML2_IDP_x509', 'MIID/TCCAuWgAwIBAgIJAI4R3WyjjmB1MA0GCSqGSIb3DQEBCwUAMIGUMQswCQYDVQQGEwJBUjEVMBMGA1UECAwMQnVlbm9zIEFpcmVzMRUwEwYDVQQHDAxCdWVub3MgQWlyZXMxDDAKBgNVBAoMA1NJVTERMA8GA1UECwwIU2lzdGVtYXMxFDASBgNVBAMMC09yZy5TaXUuQ29tMSAwHgYJKoZIhvcNAQkBFhFhZG1pbmlAc2l1LmVkdS5hcjAeFw0xNDEyMDExNDM2MjVaFw0yNDExMzAxNDM2MjVaMIGUMQswCQYDVQQGEwJBUjEVMBMGA1UECAwMQnVlbm9zIEFpcmVzMRUwEwYDVQQHDAxCdWVub3MgQWlyZXMxDDAKBgNVBAoMA1NJVTERMA8GA1UECwwIU2lzdGVtYXMxFDASBgNVBAMMC09yZy5TaXUuQ29tMSAwHgYJKoZIhvcNAQkBFhFhZG1pbmlAc2l1LmVkdS5hcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbzW/EpEv+qqZzfT1Buwjg9nnNNVrxkCfuR9fQiQw2tSouS5X37W5h7RmchRt54wsm046PDKtbSz1NpZT2GkmHN37yALW2lY7MyVUC7itv9vDAUsFr0EfKIdCKgxCKjrzkZ5ImbNvjxf7eA77PPGJnQ/UwXY7W+cvLkirp0K5uWpDk+nac5W0JXOCFR1BpPUJRbz2jFIEHyChRt7nsJZH6ejzNqK9lABEC76htNy1Ll/D3tUoPaqo8VlKW3N3MZE0DB9O7g65DmZIIlFqkaMH3ALd8adodJtOvqfDU/A6SxuwMfwDYPjoucykGDu1etRZ7dF2gd+W+1Pn7yizPT1q8CAwEAAaNQME4wHQYDVR0OBBYEFPsn8tUHN8XXf23ig5Qro3beP8BuMB8GA1UdIwQYMBaAFPsn8tUHN8XXf23ig5Qro3beP8BuMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGu60odWFiK+DkQekozGnlpNBQz5lQ/bwmOWdktnQj6HYXu43e7sh9oZWArLYHEOyMUekKQAxOK51vbTHzzw66BZU91/nqvaOBfkJyZKGfluHbD0/hfOl/D5kONqI9kyTu4wkLQcYGyuIi75CJs15uA03FSuULQdY/Liv+czS/XYDyvtSLnu43VuAQWN321PQNhuGueIaLJANb2C5qq5ilTBUw6PxY9Z+vtMjAjTJGKEkE/tQs7CvzLPKXX3KTD9lIILmX5yUC3dLgjVKi1KGDqNApYGOMtjr5eoxPQrqDBmyx3flcy0dQTdLXud3UjWVW3N0PYgJtw5yBsS74QTGD4='),
    //     /*
    //      *  Instead of use the whole x509cert you can use a fingerprint
    //      *  (openssl x509 -noout -fingerprint -in "idp.crt" to generate it)
    //      */
    //     // 'certFingerprint' => '',
    // ),
}
