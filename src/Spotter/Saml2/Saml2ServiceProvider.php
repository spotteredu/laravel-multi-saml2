<?php

namespace Spotter\Saml2;

use OneLogin_Saml2_Auth;
use Spotter\Saml2\Http\Middleware\SubdomainBindSaml;
use Illuminate\Support\ServiceProvider;

class Saml2ServiceProvider extends ServiceProvider
{

    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        include __DIR__ . '/../../routes.php';

        $this->app['router']->middleware('samlSubdomain', SubdomainBindSaml::class);

        $this->publishes([
            __DIR__.'/../../config/saml2.php' => config_path('saml2.php'),
        ]);

        if (config('saml2.proxyVars', false)) {
            \OneLogin_Saml2_Utils::setProxyVars(true);
        }
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {

    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return [];
    }
}
