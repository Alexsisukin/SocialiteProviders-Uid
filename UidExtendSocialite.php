<?php

namespace alexsisukin\SocialiteProviders\Uid;

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
