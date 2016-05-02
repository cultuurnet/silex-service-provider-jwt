<?php

namespace CultuurNet\SilexServiceProviderJwt;

use CultuurNet\SymfonySecurityJwt\Authentication\JwtAuthenticationProvider;
use CultuurNet\SymfonySecurityJwt\Firewall\JwtListener;
use CultuurNet\UDB3\Jwt\JwtDecoderService;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\ValidationData;
use Silex\Application;
use Silex\ServiceProviderInterface;

class JwtServiceProvider implements ServiceProviderInterface
{
    /**
     * @param Application $app
     */
    public function register(Application $app)
    {
        $app['security.authentication_listener.factory.jwt'] = $app->protect(
            function ($name, $options) use ($app) {
                $app['security.validation_data.' . $name . '.jwt'] = $app->share(
                    function () use ($options) {
                        $validationData = new ValidationData();

                        $claims = isset($options['validation']) ? $options['validation'] : [];
                        foreach ($claims as $claim => $value) {
                            switch ($claim) {
                                case 'jti':
                                    $validationData->setId($value);
                                    break;

                                case 'iss':
                                    $validationData->setIssuer($value);
                                    break;

                                case 'aud':
                                    $validationData->setAudience($value);
                                    break;

                                case 'sub':
                                    $validationData->setSubject($value);
                                    break;

                                case 'current_time':
                                    $validationData->setCurrentTime($value);
                                    break;
                            }
                        }

                        return $validationData;
                    }
                );

                $app['security.public_key.' . $name . '.jwt'] = $app->share(
                    function () use ($options) {
                        return new Key($options['public_key']);
                    }
                );

                $app['security.token_decoder.' . $name . '.jwt'] = $app->share(
                    function (Application $app) use ($name, $options) {
                        return new JwtDecoderService(
                            new Parser(),
                            $app['security.validation_data.' . $name . '.jwt'],
                            new Sha256(),
                            $app['security.public_key.' . $name . '.jwt'],
                            $options['required_claims']
                        );
                    }
                );

                // define the authentication provider object
                $app['security.authentication_provider.' . $name . '.jwt'] = $app->share(
                    function () use ($app, $name) {
                        return new JwtAuthenticationProvider(
                            $app['security.token_decoder.' . $name . '.jwt']
                        );
                    }
                );

                // define the authentication listener object
                $app['security.authentication_listener.' . $name . '.jwt'] = $app->share(
                    function () use ($app, $name) {
                        return new JwtListener(
                            $app['security.token_storage'],
                            $app['security.authentication_manager'],
                            $app['security.token_decoder.' . $name . '.jwt']
                        );
                    }
                );

                return [
                    // the authentication provider id
                    'security.authentication_provider.' . $name . '.jwt',
                    // the authentication listener id
                    'security.authentication_listener.' . $name . '.jwt',
                    // the entry point id
                    null,
                    // the position of the listener in the stack
                    'pre_auth'
                ];
            }
        );
    }

    /**
     * @param Application $app
     */
    public function boot(Application $app)
    {
    }
}
