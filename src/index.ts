import {readdir} from 'node:fs/promises';
import {homedir, type} from 'node:os';
import {join} from 'node:path';
import {env} from 'node:process';
import {Drive as Device, list as listDevice} from 'drivelist';

export type Uname = 'Linux' | 'Darwin' | 'Windows NT';

export type SavePaths = {
	device?: Device;
	paths: string[];
};

export type DriveCertificate = {
	device?: Device;
	savePath: string;
	issuerId: string;
	distinguishedName: string;
	signPublicKeyPath?: string;
	signPrivateKeyPath?: string;
	keyDistributionPublicKeyPath?: string;
	keyDistributionPrivateKeyPath?: string;
};

export function getPrimaryDriveSavePath(os: Uname = type() as Uname): string {
	return join(homedir(), os === 'Windows NT' ? 'AppData\\LocalLow\\NPKI' : (os === 'Darwin' ? 'Library/Preferences/NPKI' : 'NPKI'));
}

export async function listExternalDriveSavePaths(): Promise<SavePaths[]> {
	const result: SavePaths[] = [];

	for (const device of await listDevice()) {
		if (device.isUSB) {
			const paths = [];

			for (const mountpoint of device.mountpoints) {
				paths.push(join(mountpoint.path, 'NPKI'));
			}

			result.push({
				device,
				paths,
			});
		}
	}

	return result;
}

export async function listDriveSavePaths(): Promise<SavePaths[]> {
	return [{paths: [getPrimaryDriveSavePath()]}, ...await listExternalDriveSavePaths()];
}

export function getSecurityTokenEnvironmentFilePath(os: Uname = type() as Uname): string {
	return os === 'Windows NT' ? join(env.SYSTEMROOT ?? env.WINDIR ?? 'C:\\Windows', 'System32', 'npki_pkcs11.cnf') : join(homedir(), '.npki_pkcs11.cnf');
}

export async function listDriveCertificates(): Promise<DriveCertificate[]> {
	const result: DriveCertificate[] = [];

	for (const savePaths of await listDriveSavePaths()) {
		for (const savePath of savePaths.paths) {
			for (const {isDirectory, name: issuerId} of await readdir(savePath, {withFileTypes: true})) { // eslint-disable-line no-await-in-loop
				if (!isDirectory()) {
					continue;
				}

				const userCertificatesRoot = join(savePath, issuerId, 'USER');

				for (const {isDirectory, name: distinguishedName} of await readdir(userCertificatesRoot, {withFileTypes: true})) { // eslint-disable-line no-await-in-loop
					if (!isDirectory()) {
						continue;
					}

					const path = join(userCertificatesRoot, distinguishedName);

					result.push({
						device: savePaths.device,
						savePath,
						issuerId,
						distinguishedName,
						signPublicKeyPath: join(path, 'signCert.der'), // TODO: case insensitivity and basic existence support
						signPrivateKeyPath: join(path, 'signPri.key'), // TODO: same
						keyDistributionPublicKeyPath: join(path, 'kmCert.der'), // TODO: same
						keyDistributionPrivateKeyPath: join(path, 'kmPri.key'), // TODO: same
					});
				}
			}
		}
	}

	return result;
}
