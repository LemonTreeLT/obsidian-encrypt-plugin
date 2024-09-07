import {
	App,
	Component,
	MarkdownRenderer,
	MarkdownView,
	Modal,
	Notice,
	Plugin,
	PluginSettingTab,
	Setting,
	TFile
} from 'obsidian';
import * as crypto from "node:crypto";

interface EncryptSetting {
	showConfirmPassword: boolean
}

const DEFAULT_SETTINGS: EncryptSetting = {
	showConfirmPassword: true
}

// noinspection JSUnusedGlobalSymbols
export default class Encrypt extends Plugin {
	settings: EncryptSetting

	async loadSettings() {
		this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
	}

	async saveSettings() {
		await this.saveData(this.settings);
	}

	async onload() {
		await this.loadSettings()

		this.addSettingTab(new EncryptionSettingTab(this.app, this))

		this.addCommand({
			id: 'preview-file',
			name: 'Preview file',
			checkCallback: (checking: boolean) => {
				const markdownView = this.app.workspace.getActiveViewOfType(MarkdownView);
				if (!markdownView) return false;
				if (checking) return true;

				const file = markdownView.file;
				if (file) {
					this.app.vault.read(file).then(fileContent => {
						new PasswordPromptModal("Enter Password to Preview File",
							this.app,
							file,
							fileContent,
							true,
							(encryptedText) => {
								new FileContentModal(this.app, file.path, file.name.replace(".md", ""), encryptedText).open();
							}).open();
					});
				}
			}
		});

		this.addCommand({
			id: "encrypt-file",
			name: 'Encrypt file',
			checkCallback: (checking: boolean) => {
				const markdownView = this.app.workspace.getActiveViewOfType(MarkdownView);
				if (!markdownView) return false
				if (checking) return true

				const file = markdownView.file;
				if (file) {
					this.app.vault.read(file).then(fileContent => {
						new PasswordModal(this.app, file, fileContent, this.settings.showConfirmPassword, (password) => {
							const encryptedText = encrypt(fileContent, password);
							const finalContent = `**THIS FILE HAS BEEN ENCRYPTED**\n**DO NOT EDIT THESE CIPHERTEXT**\n**Encrypt Engine Version: ${ENCRYPTION_ENGINE_VERSION}**\n\n---\n\n${encryptedText}`;
							this.app.vault.modify(file, finalContent);
						}).open();
					});
				}
			}
		});

		this.addCommand({
			id: 'restore-text',
			name: 'Restore Text',
			checkCallback: (checking: boolean) => {
				const markdownView = this.app.workspace.getActiveViewOfType(MarkdownView);
				if (!markdownView) return false;
				if (checking) return true;

				const file = markdownView.file;
				if (file) {
					this.app.vault.read(file).then(fileContent => {
						new PasswordPromptModal("Enter Password to Restore",
							this.app,
							file,
							fileContent,
							false,
							(encryptedText) => {
								this.app.vault.modify(file, encryptedText);
							}).open();
					});
				}
			}
		})
	}
}

class PasswordPromptModal extends Modal {
	file: TFile;
	fileContent: string;
	forcedDecrypt: boolean;
	onSubmit: (encryptedText: string) => void;

	constructor(title: string,
				app: App,
				file: TFile,
				fileContent: string,
				forcedDecrypt: boolean,
				onSubmit: (encryptedText: string) => void) {
		super(app);
		this.file = file;
		this.fileContent = fileContent;
		this.onSubmit = onSubmit;
		this.setTitle(title);
		this.forcedDecrypt = forcedDecrypt;

	}

	onOpen() {
		const {contentEl} = this;
		let passwordInput = contentEl.createEl('input', {
			type: 'password',
			placeholder: 'Password',
			cls: 'password-modal-input'
		});

		const buttonContainer = contentEl.createDiv({cls: 'password-modal-buttons'});
		const confirmButton = buttonContainer.createEl('button', {text: 'Confirm', cls: 'password-modal-button'});
		const cancelButton = buttonContainer.createEl('button', {text: 'Cancel', cls: 'password-modal-button'});
		const forcedDecryptButton = buttonContainer.createEl('button', {text: 'Forced', cls: 'forced-decrypt-button'});

		forcedDecryptButton.hide()

		forcedDecryptButton.onclick = () => {
			const decryptedText = forcedDecrypt(extractCipherText(this.fileContent)!, passwordInput.value);
			this.onSubmit(decryptedText)
		}

		confirmButton.onclick = () => {
			const password = passwordInput.value;

			// 检查文件内容是否包含加密标识
			if (!this.fileContent.startsWith("**THIS FILE HAS BEEN ENCRYPTED**")) {
				new Notice('This file is not encrypted.');
				this.close();
				return;
			}
			// 提取密文部分
			const encryptedText = extractCipherText(this.fileContent);

			if (!encryptedText) {
				new Notice('No encrypted content found.');
				this.close();
				return;
			}

			let decryptedText = "If you see this, it means there is a bug in the plugin."

			try {
				decryptedText = decrypt(encryptedText, password);
			} catch (error) {
				new Notice("Wrong pass word or broken ciphertext.")
				if (this.forcedDecrypt) forcedDecryptButton.show()
				return;
			}

			this.onSubmit(decryptedText);
			this.close();
		};

		cancelButton.onclick = () => {
			this.close();
		};
	}

	onClose() {
		const {contentEl} = this;
		contentEl.empty();
	}
}

class PasswordModal extends Modal {
	file: TFile;
	fileContent: string;
	showConfirmPassword: boolean;
	onSubmit: (password: string) => void;

	constructor(app: App,
				file: TFile,
				fileContent: string,
				showConfirmPassword: boolean,
				onSubmit: (password: string) => void) {
		super(app);
		this.file = file;
		this.fileContent = fileContent;
		this.showConfirmPassword = showConfirmPassword;
		this.onSubmit = onSubmit;
		this.setTitle("Enter Password to Encrypt")
	}

	onOpen() {
		const {contentEl} = this;

		let passwordInput = contentEl.createEl('input', {
			type: 'password',
			placeholder: 'Password',
			cls: 'password-modal-input'
		});
		let confirmPasswordInput: HTMLInputElement | null = null;

		if (this.showConfirmPassword) {
			confirmPasswordInput = contentEl.createEl('input', {
				type: 'password',
				placeholder: 'Confirm Password',
				cls: 'password-modal-input'
			});
		}

		const buttonContainer = contentEl.createDiv({cls: 'password-modal-buttons'});
		const confirmButton = buttonContainer.createEl('button', {text: 'Confirm', cls: 'password-modal-button'});
		const cancelButton = buttonContainer.createEl('button', {text: 'Cancel', cls: 'password-modal-button'});

		// 设置按钮的点击事件
		confirmButton.onclick = () => {
			const password = passwordInput.value;
			if (this.showConfirmPassword && confirmPasswordInput && password !== confirmPasswordInput.value) {
				new Notice('Passwords do not match!');
				return;
			}
			this.onSubmit(password);
			this.close();
		};

		cancelButton.onclick = () => {
			this.close();
		};
	}

	onClose() {
		const {contentEl} = this;
		contentEl.empty();
	}
}

class FileContentModal extends Modal {
	fileName: string;
	fileContent: string;
	filePath: string;

	constructor(app: App, filePath: string, fileName: string, fileContent: string) {
		super(app);
		this.fileName = fileName;
		this.fileContent = fileContent;
		this.filePath = filePath;
		this.setTitle(fileName)
	}

	onOpen() {
		// this.contentEl.createEl('h1', {text: this.fileName});

		MarkdownRenderer.render(
			this.app,
			this.fileContent,
			this.contentEl.createDiv(),
			this.filePath,
			new Component()
		).then(r => console.log(r));
	}

	onClose() {
		const {contentEl} = this;
		contentEl.empty();
	}
}

// 用于添加设置页面
class EncryptionSettingTab extends PluginSettingTab {
	plugin: Encrypt;

	constructor(app: App, plugin: Encrypt) {
		super(app, plugin);
		this.plugin = plugin;
	}

	display(): void {
		const {containerEl} = this;

		containerEl.empty();

		containerEl.createEl('h2', {text: 'Encryption Settings'});

		new Setting(containerEl)
			.setName('Show Confirm Password')
			.setDesc('Enable or disable the confirm password field during encryption')
			.addToggle(toggle => toggle
				.setValue(this.plugin.settings.showConfirmPassword)
				.onChange(async (value) => {
					this.plugin.settings.showConfirmPassword = value;
					await this.plugin.saveSettings();
				}));
	}
}

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;
const HASH_LENGTH = 64;
const ENCRYPTION_ENGINE_VERSION = 1

function getKeyFromString(key: string): Buffer {
	return crypto.createHash('sha256').update(key).digest();
}

function encrypt(text: string, keyString: string): string {
	const key = getKeyFromString(keyString);
	const iv = crypto.randomBytes(IV_LENGTH);
	const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

	// 计算明文的 SHA-256 校验和
	const hash = crypto.createHash('sha256').update(text).digest('hex');
	const plaintextWithHash = hash + text;

	// 加密
	let encrypted = cipher.update(plaintextWithHash, 'utf8', 'hex');
	encrypted += cipher.final('hex');

	return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText: string, keyString: string): string {
	const key = getKeyFromString(keyString);
	const parts = encryptedText.split(':');
	const iv = Buffer.from(parts[0], 'hex');
	const encrypted = parts[1];
	const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);

	// 解密
	let decryptedWithHash = decipher.update(encrypted, 'hex', 'utf8');
	decryptedWithHash += decipher.final('utf8');

	// 验证校验和
	const originalHash = decryptedWithHash.substring(0, HASH_LENGTH);
	const plaintext = decryptedWithHash.substring(HASH_LENGTH);

	const computedHash = crypto.createHash('sha256').update(plaintext).digest('hex');

	if (originalHash === computedHash) return plaintext;
	else throw new Error("Failed to encrypt: Wrong pass word or broken ciphertext.");
}

function forcedDecrypt(encryptedText: string, keyString: string): string {
	const key = getKeyFromString(keyString);
	const parts = encryptedText.split(':');
	const iv = Buffer.from(parts.shift()!, 'hex');
	const encrypted = parts.join(':');

	const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
	let decrypted = decipher.update(encrypted, 'hex', 'utf8');
	decrypted += decipher.final('utf8');

	return decrypted;
}

function extractCipherText(fileContent: string): string | null {
	const parts = fileContent.split('---');

	// 获取分隔符 '---' 后的密文部分
	if (parts.length > 1) return parts[1].trim();

	return null;
}
