(() => {
  const button = document.getElementById('copy');
  const label = button.querySelector('span');
  const icon = button.querySelector('use');
  const commands = document.getElementById('commands');
  const status = document.getElementById('copy-status');
  button.hidden = false;
  let reset;

  button.addEventListener('click', async () => {
    clearTimeout(reset);
    try {
      await navigator.clipboard.writeText(commands.textContent);
      button.dataset.state = 'copied';
      label.textContent = '已复制';
      icon.setAttribute('href', '#icon-check');
      status.textContent = '安装命令已复制。';
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(commands);
      selection.removeAllRanges();
      selection.addRange(range);
      label.textContent = '按 ⌘C 复制';
      status.textContent = '已选中安装命令，请按 Command C 复制。';
    }
    reset = setTimeout(() => {
      delete button.dataset.state;
      label.textContent = '复制命令';
      icon.setAttribute('href', '#icon-copy');
      status.textContent = '';
    }, 3200);
  });
})();
