<?php
/**
* @author Sujith Haridasan <sharidasan@owncloud.com>
*
* @copyright Copyright (c) 2017, ownCloud GmbH
* @license AGPL-3.0
*
* This code is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License, version 3,
* as published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License, version 3,
* along with this program.  If not, see <http://www.gnu.org/licenses/>
*
*/


namespace OCA\Encryption\Command;

use OC\Encryption\Exceptions\DecryptionFailedException;
use OC\Encryption\Manager;
use OC\Files\View;
use OCA\Encryption\KeyManager;
use OCA\Encryption\Util;
use OCP\App\IAppManager;
use OCP\IAppConfig;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\ISession;
use OCP\IUserManager;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class RecreateMasterKey extends Command {

	/** @var Manager  */
	protected $encryptionManager;

	/** @var IUserManager  */
	protected $userManager;

	/** @var View  */
	protected $rootView;

	/** @var KeyManager  */
	protected $keyManager;

	/** @var Util  */
	protected $util;

	/** @var  IAppManager */
	protected $IAppManager;

	/** @var  IAppConfig */
	protected $appConfig;

	/** @var IDBConnection  */
	protected $dbconnection;

	/** @var IConfig  */
	protected $IConfig;

	/** @var ISession  */
	protected $ISession;

	/** @var array files which couldn't be decrypted */
	protected $failed;

	/**
	 * RecreateMasterKey constructor.
	 *
	 * @param Manager $encryptionManager
	 * @param IUserManager $userManager
	 * @param View $rootView
	 * @param KeyManager $keyManager
	 * @param Util $util
	 * @param IAppManager $IAppManager
	 * @param IAppConfig $appConfig
	 */
	public function __construct(Manager $encryptionManager, IUserManager $userManager,
								View $rootView, KeyManager $keyManager, Util $util,
								IAppManager $IAppManager, IAppConfig $appConfig,
								IDBConnection $dbconnection, IConfig $IConfig, ISession $ISession) {

		parent::__construct();
		$this->encryptionManager = $encryptionManager;
		$this->userManager = $userManager;
		$this->rootView = $rootView;
		$this->keyManager = $keyManager;
		$this->util = $util;
		$this->IAppManager = $IAppManager;
		$this->appConfig = $appConfig;
		$this->dbconnection = $dbconnection;
		$this->IConfig = $IConfig;
		$this->ISession = $ISession;
	}

	protected function configure() {
		parent::configure();

		$this
			->setName('encryption:recreate-master-key')
			->setDescription('Replace existing master key with new one. Encrypt the file system with newly created master key')
		;
	}

	protected function execute(InputInterface $input, OutputInterface $output) {
		//echo "Decryption going to start\n";
		$output->writeln("Decryption started\n");
		$this->decryptAllUsersFiles();

		if (empty($this->failed)) {

			$this->IAppManager->disableApp('encryption');

			//Delete the files_encryption dir
			$this->rootView->deleteAll('files_encryption');

			$this->appConfig->setValue('core', 'encryption_enabled', 'no');
			$this->appConfig->deleteKey('encryption','useMasterKey');
			$this->appConfig->deleteKey('encryption','masterKeyId');
			$this->appConfig->deleteKey('encryption','recoveryKeyId');
			$this->appConfig->deleteKey('encryption','publicShareKeyId');
			$this->appConfig->deleteKey('files_encryption','installed_version');

		}
		$output->writeln("Decryption completed\n");

		//Reencrypt again
		$this->IAppManager->enableApp('encryption');
		$this->appConfig->setValue('core', 'encryption_enabled', 'yes');
		$this->appConfig->setValue('encryption', 'enabled', 'yes');
		$output->writeln("Encryption started\n");

		$sql = $this->dbconnection->getQueryBuilder();
		$sql->select('*')->from('appconfig')->where('appid="encryption"');
		$output->writeln("Waiting for creating new masterkey\n");
		$progress = new ProgressBar($output);
		$progress->start();
		while(!$this->appConfig->hasKey('encryption', 'publicShareKeyId')) {
			sleep(3);
			$progress->advance();
			$result = $sql->execute();

			$rows = $result->fetchAll();

			foreach ($rows as $row) {
				$this->IConfig->setAppValue($row['appid'], $row['configkey'],$row['configvalue']);
			}
		}
		$this->keyManager->setPublicShareKey();
		$this->keyManager->setMasterKeyId();

		$progress->finish();
		$output->writeln("\nNew masterkey created successfully\n");

		$this->appConfig->setValue('encryption','enabled', 'yes');
		$this->appConfig->setValue('encryption','useMasterKey', '1');

		$this->keyManager->validateShareKey();
		$this->keyManager->validateMasterKey();
		$this->encryptAllUsersFiles();
		$output->writeln("Encryption completed successfully\n");
	}

	public function encryptAllUsersFiles() {
		$this->encryptAllUserFilesWithMasterKey();
	}

	public function encryptAllUserFilesWithMasterKey() {
		$userNo = 1;
		foreach($this->userManager->getBackends() as $backend) {
			$limit = 500;
			$offset = 0;
			do {
				$users = $backend->getUsers('', $limit, $offset);
				foreach ($users as $user) {
					if($this->encryptionManager->isReadyForUser($user)) {
						echo "\nReady for user $user\n";
						$this->encryptUsersFiles($user);
					}
					$userNo++;
				}
				$offset += $limit;
			} while(count($users) >= $limit);
		}
	}

	public function encryptUsersFiles($uid) {

		$this->setupUserFS($uid);
		$directories = [];
		$directories[] =  '/' . $uid . '/files';

		while($root = array_pop($directories)) {
			$content = $this->rootView->getDirectoryContent($root);
			foreach ($content as $file) {
				$path = $root . '/' . $file['name'];
				if ($this->rootView->is_dir($path)) {
					$directories[] = $path;
					continue;
				} else {
					if($this->encryptFile($path) === false) {
					}
				}
			}
		}
	}

	public function encryptFile($path) {
		$source = $path;
		$target = $path . '.encrypted.' . time();

		try {
			$this->ISession->set('encryptAllCmd', true);
			$this->rootView->copy($source, $target);
			$this->rootView->rename($target, $source);
			$this->ISession->remove('encryptAllCmd');
		} catch (DecryptionFailedException $e) {
			if ($this->rootView->file_exists($target)) {
				$this->rootView->unlink($target);
			}
			return false;
		}

		return true;
	}

	protected function decryptAllUsersFiles() {
		$userList = [];

		foreach ($this->userManager->getBackends() as $backend) {
			$limit = 500;
			$offset = 0;
			do {
				$users = $backend->getUsers('', $limit, $offset);
				foreach ($users as $user) {
					$userList[] = $user;
				}
				$offset += $limit;
			} while (count($users) >= $limit);
		}

		$userNo = 1;
		foreach ($userList as $uid) {
			$this->decryptUsersFiles($uid);
			$userNo++;
		}
	}

	protected function decryptUsersFiles($uid) {
		$this->setupUserFS($uid);
		$directories = [];
		$directories[] = '/' . $uid . '/files';

		while ($root = array_pop($directories)) {
			$content = $this->rootView->getDirectoryContent($root);
			foreach ($content as $file) {
				// only decrypt files owned by the user
				if($file->getStorage()->instanceOfStorage('OCA\Files_Sharing\SharedStorage')) {
					continue;
				}
				$path = $root . '/' . $file['name'];
				if ($this->rootView->is_dir($path)) {
					$directories[] = $path;
					continue;
				} else {
					try {
						if ($file->isEncrypted() !== false) {
							if ($this->decryptFile($path) !== false) {
								//echo "\nSuccessfully decrypted $path\n";
							}
						}
					} catch (\Exception $e) {
						if (isset($this->failed[$uid])) {
							$this->failed[$uid][] = $path;
						} else {
							$this->failed[$uid] = [$path];
						}
					}
				}
			}
		}

		if (empty($this->failed)) {
			$this->rootView->deleteAll("$uid/files_encryption");
		}
	}

	protected function decryptFile($path) {

		$source = $path;
		$target = $path . '.decrypted.' . $this->getTimestamp();

		try {
			$this->ISession->set('decryptAllCmd', true);
			$this->rootView->copy($source, $target);
			$this->rootView->rename($target, $source);
			$this->keyManager->setVersion($source,0, $this->rootView);
			$this->ISession->remove('decryptAllCmd');
		} catch (DecryptionFailedException $e) {
			if ($this->rootView->file_exists($target)) {
				$this->rootView->unlink($target);
			}
			return false;
		}

		return true;
	}

	protected function getTimestamp() {
		return time();
	}

	protected function setupUserFS($uid) {
		\OC_Util::tearDownFS();
		\OC_Util::setupFS($uid);
	}
}