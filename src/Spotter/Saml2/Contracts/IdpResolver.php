<?php

namespace Spotter\Saml2\Contracts;

interface IdpResolver
{
    /**
     * Resolve the User.
     *
     * @return mixed|null
     */
    public static function idpSettings($subdomain);
}
