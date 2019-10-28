<?php
declare(strict_types=1);

namespace Flowpack\Neos\FrontendLogin\Ui\Command;

/*
 * This file is part of the Flowpack.Neos.FrontendLogin.Ui package.
 *
 * (c) Contributors of the Neos Project - www.neos.io
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Cli\CommandController;
use Neos\Flow\Security\Account;
use Neos\Neos\Domain\Exception as NeosDomainException;
use Neos\Neos\Domain\Model\User;
use Neos\Neos\Domain\Service\UserService;

/**
 * The User Command Controller
 *
 * @Flow\Scope("singleton")
 */
class UserCommandController extends CommandController
{
    /**
     * @var string
     */
    static protected $authenticationProviderName = 'Flowpack.Neos.FrontendLogin:Frontend';

    /**
     * @Flow\Inject
     * @var UserService
     */
    protected $userService;

    /**
     * Delete expired (inactive) users having only an account with the Flowpack.Neos.FrontendLogin:Frontend provider
     *
     * @return void
     * @throws NeosDomainException
     */
    public function deleteExpiredCommand(): void
    {
        $users = $this->findExpiredUsers();
        if (empty($users)) {
            $this->outputLine('No expired users found.');
            $this->quit(0);
        }

        foreach ($users as $user) {
            $username = $this->userService->getUsername($user, self::$authenticationProviderName);

            $this->userService->deleteUser($user);
            $this->outputLine('Deleted user "%s".', [$username]);
        }
    }

    /**
     * Find all expired users
     *
     * @return array<User>
     */
    protected function findExpiredUsers(): array
    {
        return array_filter(
            $this->userService->getUsers()->toArray(),
            static function (User $user) {
                $accounts = $user->getAccounts();
                if (count($accounts) === 1) {
                    /** @var Account $account */
                    $account = $accounts->first();
                    return $account->isActive() === false && $account->getAuthenticationProviderName() === self::$authenticationProviderName;
                }
                return false;
            }
        );
    }
}
