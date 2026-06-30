<script lang="ts">
  import { browser } from "$app/environment";

  import SunIcon from "@lucide/svelte/icons/sun";
  import MoonIcon from "@lucide/svelte/icons/moon";

  import { Button } from "$lib/components/ui/button/index.js";

  const KEY = "omeduo_theme";
  let dark = $state(browser ? localStorage.getItem(KEY) : undefined);

  $effect(() => {
    if (browser && localStorage) {
      if (dark) localStorage.setItem(KEY, dark);
      document.documentElement.classList.toggle(
        "dark",
        dark === "dark" || (!dark && window.matchMedia("(prefers-color-scheme: dark)").matches)
      );
    }
  });

  // Cursed
  function toggleMode() {
    if (!browser) return;

    if (dark) dark = dark === "dark" ? "light" : "dark";
    else dark = window.matchMedia("(prefers-color-scheme: dark)").matches ? "light" : "dark";
  }

  let { visible = true } = $props();
</script>

{#if visible}
  <Button onclick={toggleMode} variant="outline" size="icon">
    <SunIcon
      class="h-[1.2rem] w-[1.2rem] scale-100 rotate-0 transition-all! dark:scale-0 dark:-rotate-90"
    />
    <MoonIcon
      class="absolute h-[1.2rem] w-[1.2rem] scale-0 rotate-90 transition-all! dark:scale-100 dark:rotate-0"
    />
    <span class="sr-only">Toggle theme</span>
  </Button>
{/if}
