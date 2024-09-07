import {App, MarkdownRenderer, Modal, Plugin, MarkdownView, Component} from 'obsidian';

export default class MyPlugin extends Plugin {
	async onload() {
		this.addCommand({
			id: 'read-file',
			name: 'Read file',
			checkCallback: (checking: boolean) => {
				const markdownView = this.app.workspace.getActiveViewOfType(MarkdownView);
				if (!markdownView) return false
				if (checking) return true

				const file = markdownView.file;
				if (file) {
					this.app.vault.read(file).then(fileContent => {
						new FileContentModal(this.app, file.path, file.name.replace(".md", ""), fileContent).open();
					});
				}

			}
		});
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
	}

	onOpen() {
		const {contentEl} = this;

		// 文件名作为一级标题
		contentEl.createEl('h1', {text: this.fileName});

		// 创建一个空的div来渲染Markdown
		const markdownContainer = contentEl.createDiv();

		// 使用新的MarkdownRenderer.render方法来渲染Markdown内容
		MarkdownRenderer.render(
			this.app,               // 当前的应用实例
			this.fileContent,        // 要渲染的Markdown内容
			markdownContainer,       // 渲染到的HTML元素
			this.filePath,           // 当前文件的路径
			new Component()                     // 当前的Modal上下文 (组件实例)
		);
	}

	onClose() {
		const {contentEl} = this;
		contentEl.empty();
	}
}
