<?php
/**
 * @author Piotr Mrowczynski <Piotr.Mrowczynski@owncloud.com>
 *
 * @copyright Copyright (c) 2016, ownCloud GmbH.
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

namespace OCA\DAV\Files;

use OCA\DAV\Connector\Sabre\Exception\FileLocked;
use OCP\Files\StorageNotAvailableException;
use OCP\Lock\ILockingProvider;
use OCP\Lock\LockedException;
use Sabre\DAV\Exception;
use Sabre\DAV\Exception\Forbidden;
use Sabre\DAV\Exception\ServiceUnavailable;
use OCA\DAV\Connector\Sabre\File;
use OCA\DAV\Connector\Sabre\Exception\EntityTooLarge;
use OCA\DAV\Connector\Sabre\Exception\Forbidden as DAVForbiddenException;
use OCA\DAV\Connector\Sabre\Exception\UnsupportedMediaType;
use OCP\Files\ForbiddenException;
use Sabre\DAV\Exception\BadRequest;

class BundledFile extends File {

	/**
	 * Updates the data
	 *
	 * The $data['data] argument is a readable stream resource.
	 * The other $data key-values should be header fields in form of string
	 *
	 * After a successful put operation, you may choose to return an ETag. The
	 * etag must always be surrounded by double-quotes. These quotes must
	 * appear in the actual string you're returning.
	 *
	 * Clients may use the ETag from a PUT request to later on make sure that
	 * when they update the file, the contents haven't changed in the mean
	 * time.
	 *
	 * If you don't plan to store the file byte-by-byte, and you return a
	 * different object on a subsequent GET you are strongly recommended to not
	 * return an ETag, and just return null.
	 *
	 * @param array $data
	 *
	 * @throws Forbidden
	 * @throws UnsupportedMediaType
	 * @throws BadRequest
	 * @throws Exception
	 * @throws EntityTooLarge
	 * @throws ServiceUnavailable
	 * @throws FileLocked
	 * @return array $properties
	 */
	public function putFile($data) {
		$properties = array();
		try {
			$exists = $this->fileView->file_exists($this->path);
			if ($this->info && $exists && !$this->info->isUpdateable()) {
				throw new Forbidden();
			}
		} catch (StorageNotAvailableException $e) {
			throw new ServiceUnavailable("File is not updatable: " . $e->getMessage());
		}

		// verify path of the target
		$this->verifyPath();
		
		$partFilePath = $this->getPartFileBasePath($this->path) . '.ocTransferId' . rand();

		// the part file and target file might be on a different storage in case of a single file storage (e.g. single file share)
		/** @var \OC\Files\Storage\Storage $partStorage */
		list($partStorage, $internalPartPath) = $this->fileView->resolvePath($partFilePath);
		/** @var \OC\Files\Storage\Storage $storage */
		list($storage, $internalPath) = $this->fileView->resolvePath($this->path);
		try {
			$target = $partStorage->fopen($internalPartPath, 'wb');
			if ($target === false) {
				\OCP\Util::writeLog('webdav', '\OC\Files\Filesystem::fopen() failed', \OCP\Util::ERROR);
				// because we have no clue about the cause we can only throw back a 500/Internal Server Error
				throw new Exception('Could not write file contents');
			}
			list($count, $result) = \OC_Helper::streamCopy($data['data'], $target);
			fclose($target);

			if ($result === false) {
				$expected = -1;
				if (isset($data['content-length'])) {
					$expected = $data['content-length'];
				}
				throw new Exception('Error while copying file to target location (copied bytes: ' . $count . ', expected filesize: ' . $expected . ' )');
			}

			// if content length is sent by client:
			// double check if the file was fully received
			// compare expected and actual size
			if (isset($data['content-length'])) {
				$expected = $data['content-length'];
				if ($count != $expected) {
					throw new BadRequest('Expected filesize ' . $expected . ' got ' . $count);
				}
			}

		} catch (\Exception $e) {
			$partStorage->unlink($internalPartPath);
			$this->convertToSabreException($e);
		}

		try {
			$view = \OC\Files\Filesystem::getView();
			if ($view) {
				$run = $this->emitPreHooks($exists);
			} else {
				$run = true;
			}

			try {
				$this->changeLock(ILockingProvider::LOCK_EXCLUSIVE);
			} catch (LockedException $e) {
				$partStorage->unlink($internalPartPath);
				throw new FileLocked($e->getMessage(), $e->getCode(), $e);
			}

			try {
				if ($run) {
					$renameOkay = $storage->moveFromStorage($partStorage, $internalPartPath, $internalPath);
					$fileExists = $storage->file_exists($internalPath);
				}
				if (!$run || $renameOkay === false || $fileExists === false) {
					\OCP\Util::writeLog('webdav', 'renaming part file to final file failed', \OCP\Util::ERROR);
					throw new Exception('Could not rename part file to final file');
				}
			} catch (ForbiddenException $ex) {
				throw new DAVForbiddenException($ex->getMessage(), $ex->getRetry());
			} catch (\Exception $e) {
				$partStorage->unlink($internalPartPath);
				$this->convertToSabreException($e);
			}

			// since we skipped the view we need to scan and emit the hooks ourselves
			$storage->getUpdater()->update($internalPath);

			try {
				$this->changeLock(ILockingProvider::LOCK_SHARED);
			} catch (LockedException $e) {
				throw new FileLocked($e->getMessage(), $e->getCode(), $e);
			}

			if ($view) {
				$this->emitPostHooks($exists);
			}

			// allow sync clients to send the mtime along in a header
			$request = \OC::$server->getRequest();
			if (isset($data['x-oc-mtime'])) {
				if ($this->fileView->touch($this->path, $data['x-oc-mtime'])) {
					$properties['{DAV:}x-oc-mtime'] = 'accepted';
				}
			}

			$this->refreshInfo();

			if (isset($data['x-oc-checksum'])) {
				$checksum = trim($data['x-oc-checksum']);
				$this->fileView->putFileInfo($this->path, ['checksum' => $checksum]);
				$this->refreshInfo();
			} else if ($this->getChecksum() !== null && $this->getChecksum() !== '') {
				$this->fileView->putFileInfo($this->path, ['checksum' => '']);
				$this->refreshInfo();
			}

		} catch (StorageNotAvailableException $e) {
			throw new ServiceUnavailable("Failed to check file size: " . $e->getMessage());
		}

		$etag = $this->getEtag();
		$properties['{DAV:}etag'] = $etag;
		$properties['{DAV:}oc-etag'] = $etag;
		$properties['{DAV:}oc-fileid'] = $this->getFileId();
		return $properties;
	}

	/*
	 * @param resource $data
	 *
	 * @throws Forbidden
	 */
	public function put($data) {
		throw new Forbidden('PUT method not supported for bundling');
	}
}