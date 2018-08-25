<?php

namespace AlexSisukin\SocialiteProviders\uid;

use Illuminate\Support\Arr;
use Laravel\Socialite\Two\ProviderInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider implements ProviderInterface
{
    private $oauth_nonce;

    private $timestamp;

    private $sig_method = 'HMAC-SHA1';

    private $oauth_version = '1.0';

    private $main_url = 'https://uapi.ucoz.com';

    private $oauth_token_secret;
    private $oauth_verifier;
    private $oauth_token;

    protected $stateless = true;
    /**
     * Unique Provider Identifier.
     */
    const IDENTIFIER = 'UID';

    /**
     * {@inheritdoc}
     */
    protected $scopes = ['email'];

    /**
     * Last API version.
     */
    const VERSION = '5.78';

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            $this->main_url . '/accounts/OAuthAuthorizeToken', $state
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->main_url . '/accounts/OAuthGetAccessToken';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($tokens)
    {

        $this->set_oauth_token($tokens['oauth_token']);
        $this->set_oauth_token_secret($tokens['oauth_token_secret']);

        $parametrs = array(
            'oauth_consumer_key' => $this->clientId, //обязательный параметр
            'oauth_nonce' => $this->get_oauth_nonce(), //обязательный параметр
            'oauth_signature_method' => $this->sig_method, //обязательный параметр
            'oauth_timestamp' => $this->get_timestamp(), //обязательный параметр
            'oauth_token' => $this->oauth_token, //обязательный параметр
            'oauth_version' => $this->oauth_version, //обязательный параметр
        );
        ksort($parametrs);
        $contents = $this->uAPIModule('/accounts/GetUserInfo', 'get', $parametrs, '');
        $response = json_decode($contents, true);
        if (!is_array($response) || !isset($response['uid'])) {
            throw new \RuntimeException(sprintf(
                'Invalid JSON response from Uid: %s',
                $contents
            ));
        }
        return $response;
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id' => Arr::get($user, 'uid'),
            'nickname' => Arr::get($user, 'nickname'),
            'name' => trim(Arr::get($user, 'first_name') . ' ' . Arr::get($user, 'last_name')),
            'email' => Arr::get($user, 'email'),
            'avatar' => Arr::get($user, 'avatar'),
        ]);
    }


    /**
     * {@inheritdoc}
     */
    public static function additionalConfigKeys()
    {
        return ['lang'];
    }

    protected function getCodeFields($state = null)
    {
        $parametrs = array(
            'oauth_consumer_key' => $this->clientId, //обязательный параметр
            'oauth_nonce' => $this->get_oauth_nonce(), //обязательный параметр
            'oauth_signature_method' => $this->sig_method, //обязательный параметр
            'oauth_timestamp' => $this->get_timestamp(), //обязательный параметр
            'oauth_version' => $this->oauth_version, //обязательный параметр
            'oauth_callback' => $this->redirectUrl
        );
        ksort($parametrs);
        $uAPIcurlresult = $this->uAPIModule('/accounts/OAuthGetRequestToken', 'post', $parametrs, '');
        $obj = json_decode($uAPIcurlresult, true);
        $this->oauth_token = $obj['oauth_token'];
        $this->oauth_token_secret = $obj['oauth_token_secret'];
        SetCookie("uAPIlogin", "$this->oauth_token_secret", time() + 3600);
        $fields = [
            'oauth_token' => $this->oauth_token, 'oauth_token_secret' => $this->oauth_token_secret
        ];

        if ($this->usesState()) {
            $fields['state'] = $state;
        }

        return array_merge($fields, $this->parameters);
    }

    private function get_oauth_nonce()
    {
        return $this->oauth_nonce = md5(microtime() . mt_rand()); //не изменять
    }

    public function get_timestamp()
    {
        return $this->timestamp = time();
    }

    public function uAPIModule($request_url, $method, $parametrs, $format)
    {
        $request_url = $this->main_url . mb_strtolower(trim($request_url));
        $method = mb_strtoupper($method);
        $basestring = str_replace('+', '%20', http_build_query($parametrs));
        $basestring = $method . '&' . urlencode($request_url) . '&' . urlencode($basestring);
        $hash_key = $this->clientSecret . '&' . $this->oauth_token_secret;
        $oauth_signature = urlencode(trim(base64_encode(hash_hmac('sha1', $basestring, $hash_key, true))));
        $parametrs_forurl = http_build_query($parametrs);
        $url = $request_url . '?oauth_signature=' . $oauth_signature;
        $url_for = $request_url . '?' . $parametrs_forurl . '&oauth_signature=' . $oauth_signature;
        $curl = curl_init();
        switch ($method) {

            case 'GET':
                $parametrs = http_build_query($parametrs);
                curl_setopt($curl, CURLOPT_URL, $url_for);
                curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
                $uAPIcurlresult = curl_exec($curl);
                return $uAPIcurlresult;
                break;

            case 'POST':
                $parametrs = http_build_query($parametrs);
                curl_setopt($curl, CURLOPT_URL, $url);
                curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($curl, CURLOPT_POST, true);
                curl_setopt($curl, CURLOPT_POSTFIELDS, $parametrs);
                $uAPIcurlresult = curl_exec($curl);
                return $uAPIcurlresult;

                break;

            case 'PUT':
                curl_setopt($curl, CURLOPT_URL, $url_for);
                curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($curl, CURLOPT_PUT, true);
                curl_setopt($curl, CURLOPT_POSTFIELDS, '');
                $uAPIcurlresult = curl_exec($curl);
                return $uAPIcurlresult;
                break;

            case 'DELETE':

                curl_setopt($curl, CURLOPT_URL, $url_for);
                curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'DELETE');
                $uAPIcurlresult = curl_exec($curl);
                return $uAPIcurlresult;

                break;


            default:
                return null;
                break;


        }
        curl_close($curl);
    }

    public function getAccessTokenResponse($code)
    {
        $this->oauth_token = $_GET['oauth_token'];
        $this->oauth_verifier = $_GET['oauth_verifier'];
        $this->set_oauth_token_secret($_COOKIE['uAPIlogin']);
        $parametrs = array(
            'oauth_consumer_key' => $this->clientId, //обязательный параметр
            'oauth_nonce' => $this->get_oauth_nonce(), //обязательный параметр
            'oauth_signature_method' => $this->sig_method, //обязательный параметр
            'oauth_timestamp' => $this->get_timestamp(), //обязательный параметр
            'oauth_version' => $this->oauth_version, //обязательный параметр
            'oauth_token' => $this->oauth_token,
            'oauth_verifier' => $this->oauth_verifier
        );
        ksort($parametrs);
        $response = $this->uAPIModule('/accounts/OAuthGetAccessToken', 'post', $parametrs, '');


        return json_decode($response, true);
    }


    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $tokens = $this->getAccessTokenResponse($this->getCode());

        $user = $this->mapUserToObject($this->getUserByToken(
            $tokens
        ));
        return $user;
    }

    private function set_oauth_token_secret($oauth_token_secret)
    {
        $this->oauth_token_secret = $oauth_token_secret;
    }

    public function set_oauth_token($oauth_token)
    {
        $this->oauth_token = $oauth_token;
    }
}
