<?php

namespace Spotter\Saml2\Http\Controllers;

use Log;
use App;
use Spotter\Saml2\Events\Saml2LoginEvent;
use Spotter\Saml2\Saml2Auth;
use Illuminate\Routing\Controller;
use Illuminate\Http\Request;


class Saml2Controller extends Controller
{

    /**
     * Generate local sp metadata
     * @return \Illuminate\Http\Response
     */
    public function metadata(Request $request, $subdomain)
    {
        $metadata = $request->saml2Auth->getMetadata();

        return response($metadata, 200, ['Content-Type' => 'text/xml']);
    }

    /**
     * Process an incoming saml2 assertion request.
     * Fires 'Saml2LoginEvent' event if a valid user is Found
     */
    public function acs(Request $request, $subdomain)
    {
        $errors = $request->saml2Auth->acs();

        if (!empty($errors)) {
            logger()->error('saml2 error_detail', [ 'error' => $request->saml2Auth->getLastErrorReason() ]);
            logger()->error('saml2 error', $errors);
            return redirect(config('saml2.errorRoute'));
        }
        
        $user = $request->saml2Auth->getSaml2User();
        $event = new Saml2LoginEvent($user, $request->saml2Auth);

        $redirectUrl = $user->getIntendedUrl();

        if (config('saml2.loginHandler', null)) {
            return App::call(config('saml2.loginHandler'), [ $event, $subdomain ]);
        }

        event(new Saml2LoginEvent($user, $saml2Auth));

        if ($redirectUrl !== null) {
            return redirect($redirectUrl);
        } 
        else {
            return redirect(config('saml2.loginRoute'));
        }
    }

    /**
     * Process an incoming saml2 logout request.
     * Fires 'saml2.logoutRequestReceived' event if its valid.
     * This means the user logged out of the SSO infrastructure, you 'should' log him out locally too.
     */
    public function sls(Request $request, $subdomain)
    {
        $error = $request->saml2Auth->sls(config('saml2.retrieveParametersFromServer'));
        if (!empty($error)) {
            throw new \Exception("Could not log out");
        }

        return redirect(config('saml2.logoutRoute')); //may be set a configurable default
    }

    /**
     * This initiates a logout request across all the SSO infrastructure.
     */
    public function logout(Request $request, $subdomain)
    {
        $returnTo = $request->query('returnTo');
        $sessionIndex = $request->query('sessionIndex');
        $nameId = $request->query('nameId');
        $request->saml2Auth->logout($returnTo, $nameId, $sessionIndex); //will actually end up in the sls endpoint
        //does not return
    }


    /**
     * This initiates a login request
     */
    public function login(Request $request, $subdomain)
    {
        $request->saml2Auth->login(config('saml2.loginRoute'));
    }
}
