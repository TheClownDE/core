<?php
/**
 * @author Vincent Petry <pvince81@owncloud.com>
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

namespace OC\Repair;

use OCP\Migration\IOutput;
use OCP\Migration\IRepairStep;
use Doctrine\DBAL\Platforms\MySqlPlatform;

/**
 * Repairs file cache entry which path do not match the parent-child relationship
 */
class RepairMismatchFileCachePath implements IRepairStep {

	const CHUNK_SIZE = 200;

	/** @var \OCP\IDBConnection */
	protected $connection;

	/**
	 * @param \OCP\IDBConnection $connection
	 */
	public function __construct($connection) {
		$this->connection = $connection;
	}

	public function getName() {
		return 'Repair file cache entries with path that does not match parent-child relationships';
	}

	/**
	 * Fixes the broken entry.
	 *
	 * @param IOutput $out repair output
	 * @param int $fileId file id of the entry to fix
	 * @param string $wrongPath wrong path of the entry to fix
	 * @param int $correctStorageNumericId numeric idea of the correct storage
	 * @param string $correctPath value to which to set the path of the entry 
	 */
	private function fixEntryPath(IOutput $out, $fileId, $wrongPath, $correctStorageNumericId, $correctPath) {
		// delete target if exists
		$this->connection->beginTransaction();
		$qb = $this->connection->getQueryBuilder();
		$qb->delete('filecache')
			->where($qb->expr()->eq('storage', $qb->createNamedParameter($correctStorageNumericId)))
			->andWhere($qb->expr()->eq('path', $qb->createNamedParameter($correctPath)));
		$entryExisted = $qb->execute() > 0;

		$qb = $this->connection->getQueryBuilder();
		$qb->update('filecache')
			->set('path', $qb->createNamedParameter($correctPath))
			->set('path_hash', $qb->createNamedParameter(md5($correctPath)))
			->set('storage', $qb->createNamedParameter($correctStorageNumericId))
			->where($qb->expr()->eq('fileid', $qb->createNamedParameter($fileId)));
		$qb->execute();

		$text = "Fixed file cache entry with fileid $fileId, set wrong path \"$wrongPath\" to \"$correctPath\"";
		if ($entryExisted) {
			$text = " (replaced an existing entry)";
		}
		$out->advance(1, $text);

		$this->connection->commit();
	}

	private function addQueryConditions($qb) {
		// thanks, VicDeo!
		if ($this->connection->getDatabasePlatform() instanceof MySqlPlatform) {
			$concatFunction = $qb->createFunction("CONCAT(fcp.path, '/', fc.name)");
		} else {
			$concatFunction = $qb->createFunction("fcp.path || '/' || fc.name");
		}

		$qb
			->from('filecache', 'fc')
			->from('filecache', 'fcp')
			->where($qb->expr()->eq('fc.parent', 'fcp.fileid'))
			->andWhere(
				$qb->expr()->orX(
					$qb->expr()->neq(
						$qb->createFunction($concatFunction),
						'fc.path'
					),
					$qb->expr()->neq('fc.storage', 'fcp.storage')
				)
			)
			->andWhere($qb->expr()->neq('fcp.path', $qb->expr()->literal('')));
	}

	private function countResultsToProcess() {
		$qb = $this->connection->getQueryBuilder();
		$qb->select($qb->createFunction('COUNT(*)'));
		$this->addQueryConditions($qb);
		$results = $qb->execute();
		$count = $results->fetchColumn(0);
		$results->closeCursor();
		return $count;
	}

	/**
	 * Run the repair step
	 *
	 * @param IOutput $out output
	 */
	public function run(IOutput $out) {
		$totalResultsCount = 0;

		$out->startProgress($this->countResultsToProcess());

		// find all entries where the path entry doesn't match the path value that would
		// be expected when following the parent-child relationship, basically
		// concatenating the parent's "path" value with the name of the child
		$qb = $this->connection->getQueryBuilder();
		$qb->select(
			'fc.storage',
			'fc.fileid',
			// if there is a less barbaric way to do this, please let me know...
			// without this can't access parentpath as the prefixes aren't included
			// in the result array
			$qb->createFunction('fc.path as path'),
			'fc.name',
			$qb->createFunction('fcp.storage as parentstorage'),
			$qb->createFunction('fcp.path as parentpath')
		);
		$this->addQueryConditions($qb);
		$qb->setMaxResults(self::CHUNK_SIZE);

		do {
			$results = $qb->execute();
			// since we're going to operate on fetched entry, better cache them
			// to avoid DB lock ups
			$rows = $results->fetchAll();
			$results->closeCursor();

			$lastResultsCount = 0;
			foreach ($rows as $row) {
				$this->fixEntryPath(
					$out,
					$row['fileid'],
					$row['path'],
					$row['parentstorage'],
					$row['parentpath'] . '/' . $row['name']
				);
				$lastResultsCount++;
			}

			$totalResultsCount += $lastResultsCount;
		} while ($lastResultsCount === self::CHUNK_SIZE);

		if ($lastResultsCount > 0) {
			$out->info("Fixed $lastResultsCount file cache entries with wrong path");
		}
		$out->finishProgress();
	}
}
