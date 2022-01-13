<?php

declare(strict_types=1);

namespace Trikoder\Bundle\OAuth2Bundle\Security\Authenticator;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Trikoder\Bundle\OAuth2Bundle\Security\Authentication\Token\OAuth2Token;
use Trikoder\Bundle\OAuth2Bundle\Security\Authentication\Token\OAuth2TokenFactory;
use Trikoder\Bundle\OAuth2Bundle\Security\Exception\InsufficientScopesException;
use Trikoder\Bundle\OAuth2Bundle\Security\User\NullUser;

/**
 * @author Yonel Ceruto <yonelceruto@gmail.com>
 * @author Antonio J. García Lagar <aj@garcialagar.es>
 */
final class OAuth2Authenticator implements AuthenticatorInterface
{
    private $httpMessageFactory;
    private $resourceServer;
    private $oauth2TokenFactory;
    private $psr7Request;

    /**
     * @var string
     */
    private $providerKey;
    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    public function __construct(
        HttpMessageFactoryInterface $httpMessageFactory,
        ResourceServer $resourceServer,
        OAuth2TokenFactory $oauth2TokenFactory,
        UserProviderInterface $userProvider,
        string $providerKey)
    {
        $this->httpMessageFactory = $httpMessageFactory;
        $this->resourceServer = $resourceServer;
        $this->oauth2TokenFactory = $oauth2TokenFactory;
        $this->userProvider = $userProvider;
        $this->providerKey = $providerKey;
    }

    public function supports(Request $request): bool
    {
        return 0 === strpos($request->headers->get('Authorization', ''), 'Bearer ');
    }

    public function getUser($userIdentifier): UserInterface
    {
        return '' === $userIdentifier ? new NullUser() : $this->userProvider->loadUserByIdentifier($userIdentifier);
    }

    public function getCredentials(Request $request)
    {
        $psr7Request = $this->httpMessageFactory->createRequest($request);

        try {
            $this->psr7Request = $this->resourceServer->validateAuthenticatedRequest($psr7Request);
        } catch (OAuthServerException $e) {
            throw new AuthenticationException('The resource server rejected the request.', 0, $e);
        }

        return $this->psr7Request->getAttribute('oauth_user_id');
    }


    public function createToken(Passport $passport, string $firewallName): OAuth2Token
    {
        $tokenUser = $passport->getUser() instanceof NullUser ? null : $passport->getUser();

        $oauth2Token = $this->oauth2TokenFactory->createOAuth2Token($this->psr7Request, $tokenUser, $this->providerKey);

        if (!$this->isAccessToRouteGranted($oauth2Token)) {
            throw InsufficientScopesException::create($oauth2Token);
        }

        return $oauth2Token;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $this->psr7Request = null;

        throw $exception;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return $this->psr7Request = null;
    }

    private function isAccessToRouteGranted(OAuth2Token $token): bool
    {
        $routeScopes = $this->psr7Request->getAttribute('oauth2_scopes', []);

        if ([] === $routeScopes) {
            return true;
        }

        $tokenScopes = $token
            ->getAttribute('server_request')
            ->getAttribute('oauth_scopes');

        /*
         * If the end result is empty that means that all route
         * scopes are available inside the issued token scopes.
         */
        return [] === array_diff($routeScopes, $tokenScopes);
    }

    public function authenticate(Request $request)
    {
        $credentials = $this->getCredentials($request);

        return new SelfValidatingPassport(
            new UserBadge($credentials)
        );
    }

    public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        return $this->createToken($passport, $firewallName);
    }
}
