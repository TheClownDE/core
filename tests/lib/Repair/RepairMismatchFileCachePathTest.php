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
		 *     - files/source/to_move/content_to_update/sub (bogus subentry to fix)
		 *     - files/source/all_your_zombies (parent=fileid must be reparented)
		 *
		 * target storage:
		 *     - files/
		 *     - files/target/
		 *     - files/target/moved_renamed (already moved target)
		 *     - files/target/moved_renamed/content_to_update (missing until repair)
		 *
		 * if $targetExists: pre-create these additional entries:
		 *     - files/target/moved_renamed/content_to_update (will be overwritten)
		 *     - files/target/moved_renamed/content_to_update/sub (will be overwritten)
		 *     - files/target/moved_renamed/content_to_update/unrelated (will be reparented)
		 *
		 * other:
		 *     - files/source/do_not_touch (regular entry outside of the repair scope)
		 *     - files/orphaned/leave_me_alone (unrepairable unrelated orphaned entry)
		 *
		 */

		// source storage entries
		$baseId1 = $this->createFileCacheEntry($sourceStorageId, 'files');
		if ($sourceStorageId !== $targetStorageId) {
			$baseId2 = $this->createFileCacheEntry($targetStorageId, 'files');
		} else {
			$baseId2 = $baseId1;
		}
		$sourceId = $this->createFileCacheEntry($sourceStorageId, 'files/source', $baseId1);

		// target storage entries
		$targetParentId = $this->createFileCacheEntry($targetStorageId, 'files/' . $targetDir, $baseId2);

		// the move does create the parent in the target
		$targetId = $this->createFileCacheEntry($targetStorageId, 'files/' . $targetDir . '/moved_renamed', $targetParentId);

		// bogus entry: any children of the source are not properly updated
		$movedId = $this->createFileCacheEntry($sourceStorageId, 'files/source/to_move/content_to_update', $targetId);
		$movedSubId = $this->createFileCacheEntry($sourceStorageId, 'files/source/to_move/content_to_update/sub', $movedId);

		if ($targetExists) {
			// after the bogus move happened, some code path recreated the parent under a
			// different file id
			$existingTargetId = $this->createFileCacheEntry($targetStorageId, 'files/' . $targetDir . '/moved_renamed/content_to_update', $targetId);
			$existingTargetSubId = $this->createFileCacheEntry($targetStorageId, 'files/' . $targetDir . '/moved_renamed/content_to_update/sub', $existingTargetId);
			$existingTargetUnrelatedId = $this->createFileCacheEntry($targetStorageId, 'files/' . $targetDir . '/moved_renamed/content_to_update/unrelated', $existingTargetId);
		}

		$nonExistingParentId = $targetId + 100;
		$orphanedId = $this->createFileCacheEntry($targetStorageId, 'files/' . $targetDir . '/orphaned/leave_me_alone', $nonExistingParentId);

		$doNotTouchId = $this->createFileCacheEntry($sourceStorageId, 'files/source/do_not_touch', $sourceId);

		$superBogusId = $this->createFileCacheEntry($sourceStorageId, 'files/source/all_your_zombies', $sourceId);
		$qb = $this->connection->getQueryBuilder();
		$qb->update('filecache')
			->set('parent', 'fileid')
			->where($qb->expr()->eq('fileid', $qb->createNamedParameter($superBogusId)));
		$qb->execute();

		$outputMock = $this->createMock(IOutput::class);
		$this->repair->run($outputMock);

		$entry = $this->getFileCacheEntry($movedId);
		$this->assertEquals($targetId, $entry['parent']);
		$this->assertEquals((string)$targetStorageId, $entry['storage']);
		$this->assertEquals('files/' . $targetDir . '/moved_renamed/content_to_update', $entry['path']);
		$this->assertEquals(md5('files/' . $targetDir . '/moved_renamed/content_to_update'), $entry['path_hash']);

		$entry = $this->getFileCacheEntry($movedSubId);
		$this->assertEquals($movedId, $entry['parent']);
		$this->assertEquals((string)$targetStorageId, $entry['storage']);
		$this->assertEquals('files/' . $targetDir . '/moved_renamed/content_to_update/sub', $entry['path']);
		$this->assertEquals(md5('files/' . $targetDir . '/moved_renamed/content_to_update/sub'), $entry['path_hash']);

		if ($targetExists) {
			$this->assertFalse($this->getFileCacheEntry($existingTargetId));
			$this->assertFalse($this->getFileCacheEntry($existingTargetSubId));

			// unrelated folder has been reparented
			$entry = $this->getFileCacheEntry($existingTargetUnrelatedId);
			$this->assertEquals($movedId, $entry['parent']);
			$this->assertEquals((string)$targetStorageId, $entry['storage']);
			$this->assertEquals('files/' . $targetDir . '/moved_renamed/content_to_update/unrelated', $entry['path']);
			$this->assertEquals(md5('files/' . $targetDir . '/moved_renamed/content_to_update/unrelated'), $entry['path_hash']);
		}

		// orphaned entry left untouched
		$entry = $this->getFileCacheEntry($orphanedId);
		$this->assertEquals($nonExistingParentId, $entry['parent']);
		$this->assertEquals((string)$targetStorageId, $entry['storage']);
		$this->assertEquals('files/' . $targetDir . '/orphaned/leave_me_alone', $entry['path']);
		$this->assertEquals(md5('files/' . $targetDir . '/orphaned/leave_me_alone'), $entry['path_hash']);

		// "do not touch" entry left untouched
		$entry = $this->getFileCacheEntry($doNotTouchId);
		$this->assertEquals($sourceId, $entry['parent']);
		$this->assertEquals((string)$sourceStorageId, $entry['storage']);
		$this->assertEquals('files/source/do_not_touch', $entry['path']);
		$this->assertEquals(md5('files/source/do_not_touch'), $entry['path_hash']);

		// "super bogus" entry reparented
		$entry = $this->getFileCacheEntry($superBogusId);
		$this->assertEquals($sourceId, $entry['parent']);
		$this->assertEquals((string)$sourceStorageId, $entry['storage']);
		$this->assertEquals('files/source/all_your_zombies', $entry['path']);
		$this->assertEquals(md5('files/source/all_your_zombies'), $entry['path_hash']);
	}
}

