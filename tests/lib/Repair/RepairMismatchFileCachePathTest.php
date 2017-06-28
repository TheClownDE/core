<?php
/**
 * Copyright (c) 2017 Vincent Petry <pvince81@owncloud.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace Test\Repair;


use OC\Repair\RepairMismatchFileCachePath;
use OCP\Migration\IOutput;
use OCP\Migration\IRepairStep;
use Test\TestCase;

/**
 * Tests for repairing mismatch file cache paths
 *
 * @group DB
 *
 * @see \OC\Repair\RepairMismatchFileCachePath
 */
class RepairMismatchFileCachePathTest extends TestCase {

	/** @var IRepairStep */
	private $repair;

	/** @var \OCP\IDBConnection */
	private $connection;

	protected function setUp() {
		parent::setUp();

		$this->connection = \OC::$server->getDatabaseConnection();

		$this->repair = new RepairMismatchFileCachePath($this->connection);
	}

	protected function tearDown() {
		$qb = $this->connection->getQueryBuilder();
		$qb->delete('filecache')->execute();
		parent::tearDown();
	}

	private function createFileCacheEntry($storage, $path, $parent = -1) {
		$qb = $this->connection->getQueryBuilder();
		$qb->insert('filecache')
			->values([
				'storage' => $qb->createNamedParameter($storage),
				'path' => $qb->createNamedParameter($path),
				'path_hash' => $qb->createNamedParameter(md5($path)),
				'name' => $qb->createNamedParameter(basename($path)),
				'parent' => $qb->createNamedParameter($parent),
			]);
		$qb->execute();
		return $this->connection->lastInsertId('filecache');
	}

	private function getFileCacheEntry($fileId) {
		$qb = $this->connection->getQueryBuilder();
		$qb->select('*')
			->from('filecache')
			->where($qb->expr()->eq('fileid', $qb->createNamedParameter($fileId)));
		$results = $qb->execute();
		$result = $results->fetch();
		$results->closeCursor();
		return $result;
	}

	public function repairCasesProvider() {
		return [
			// same storage, different target dir
			[1, 1, 'target'],
			// different storage, same target dir name
			[1, 2, 'source'],
			// different storage, different target dir
			[1, 2, 'target'],

			// same storage, different target dir, target exists
			[1, 1, 'target', true],
			// different storage, same target dir name, target exists
			[1, 2, 'source', true],
			// different storage, different target dir, target exists
			[1, 2, 'target', true],
		];
	}

	/**
	 * Test repair
	 *
	 * @dataProvider repairCasesProvider
	 */
	public function testRepairEntry($sourceStorageId, $targetStorageId, $targetDir, $targetExists = false) {
		/*
		 * Tree:
		 *
		 * source storage:
		 *     - files/
		 *     - files/source/
		 *     - files/source/to_move (not created as we simulate that it was already moved)
		 *     - files/source/to_move/content_to_update (bogus entry to fix)
		 *
		 * target storage:
		 *     - files/
		 *     - files/target/
		 *     - files/target/moved_renamed (already moved target)
		 *     - files/target/moved_renamed/content_to_update (missing until repair)
		 *
		 * if $targetExists: pre-create files/target/moved_renamed/content_to_update
		 */

		// source storage entries
		$baseId1 = $this->createFileCacheEntry($sourceStorageId, 'files');
		if ($sourceStorageId !== $targetStorageId) {
			$baseId2 = $this->createFileCacheEntry($targetStorageId, 'files');
		} else {
			$baseId2 = $baseId1;
		}
		$this->createFileCacheEntry($sourceStorageId, 'files/source', $baseId1);

		// target storage entries
		$targetParentId = $this->createFileCacheEntry($targetStorageId, 'files/' . $targetDir, $baseId2);

		// the move does create the parent in the target
		$targetId = $this->createFileCacheEntry($targetStorageId, 'files/' . $targetDir . '/moved_renamed', $targetParentId);

		// bogus entry: any children of the source are not properly updated
		$movedId = $this->createFileCacheEntry($sourceStorageId, 'files/source/to_move/content_to_update', $targetId);

		if ($targetExists) {
			// after the bogus move happened, some code path recreated the parent under a
			// different file id
			$existingTargetId = $this->createFileCacheEntry($targetStorageId, 'files/' . $targetDir . '/moved_renamed/content_to_update', $targetId);
		}

		$outputMock = $this->createMock(IOutput::class);
		$this->repair->run($outputMock);

		$entry = $this->getFileCacheEntry($movedId);

		$this->assertEquals($targetId, $entry['parent']);
		$this->assertEquals((string)$targetStorageId, $entry['storage']);
		$this->assertEquals('files/' . $targetDir . '/moved_renamed/content_to_update', $entry['path']);
		$this->assertEquals(md5('files/' . $targetDir . '/moved_renamed/content_to_update'), $entry['path_hash']);

		if ($targetExists) {
			$this->assertFalse($this->getFileCacheEntry($existingTargetId));
		}
	}
}

