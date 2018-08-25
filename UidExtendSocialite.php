<?php

namespace AlexSisukin\SocialiteProviders\uid;

use SocialiteProviders\Manager\SocialiteWasCalled;

class UidExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param \SocialiteProviders\Manager\SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite(
            'uid', __NAMESPACE__.'\Provider'
        );
    }
}
