# Practice
笔记整理


### Color Scheme 配色方案

根据浏览器与系统设置自动切换明暗主题，也可手动切换
<div class="tx-switch">
  <button data-md-color-scheme="default"><code>Default</code></button>
  <button data-md-color-scheme="slate"><code>Slate</code></button>
</div>


---
灵感来源：https://ctf-wiki.org/

*For full documentation visit [mkdocs.org](https://www.mkdocs.org).*
*and [mkdocs-material](https://squidfunk.github.io/mkdocs-material/publishing-your-site/).*


---
<script>
  var buttons = document.querySelectorAll("button[data-md-color-scheme]")
  Array.prototype.forEach.call(buttons, function(button) {
    button.addEventListener("click", function() {
      document.body.dataset.mdColorScheme = this.dataset.mdColorScheme;
      localStorage.setItem("data-md-color-scheme",this.dataset.mdColorScheme);
    })
  })
</script>
<style>
  button[data-md-color-scheme]{
    width: 8.4rem;
    margin-bottom: .4rem;
    padding: 2.4rem .4rem .4rem;
    transition: background-color .25s,opacity .25s;
    border-radius: .2rem;
    color: #fff;
    font-size: .8rem;
    text-align: left;
    cursor: pointer;
  }
  button[data-md-color-scheme='default']{
    background-color: hsla(0, 0%, 100%, 1);
  }
  button[data-md-color-scheme='slate']{
    background-color: var(--md-default-bg-color);
  }
</style>

