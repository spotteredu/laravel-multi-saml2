<?php

Route::group([
    'prefix' => config('saml2.routesPrefix'),
    'middleware' => [ 'saml' ],
    'domain' => '{subdomain}.'.config('saml2.routesDomain')
], function () {

    Route::get('/other', function() {
        return "bitch please";
    });

    Route::get('/logout', [
        'as' => 'saml_logout',
        'uses' => 'Spotter\Saml2\Http\Controllers\Saml2Controller@logout',
    ]);

    Route::get('/login', [
        'as' => 'saml_login',
        'uses' => 'Spotter\Saml2\Http\Controllers\Saml2Controller@login',
    ]);
        
    Route::get('/metadata', [
        'as' => 'saml_metadata',
        'uses' => 'Spotter\Saml2\Http\Controllers\Saml2Controller@metadata',
    ]);

    Route::post('/acs', [
        'as' => 'saml_acs',
        'uses' => 'Spotter\Saml2\Http\Controllers\Saml2Controller@acs',
    ]);

    Route::get('/sls', [
        'as' => 'saml_sls',
        'uses' => 'Spotter\Saml2\Http\Controllers\Saml2Controller@sls',
    ]);
});