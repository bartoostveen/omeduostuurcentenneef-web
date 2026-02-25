<script>
  import Button from "$lib/components/ui/button/button.svelte";
  import DarkModeToggle from "../components/DarkModeToggle.svelte";

  import GitHubIcon from "@lucide/svelte/icons/github";
  import EmailIcon from "@lucide/svelte/icons/mail";
  import ChatIcon from "@lucide/svelte/icons/message-circle";
</script>

<main
  class="prose justify-self-center-safe p-2 py-12 prose-zinc md:prose-lg lg:prose-xl dark:prose-invert"
>
  <h1 class="justify-self-center text-center">Bart Oostveen's placeholder</h1>

  <div class="flex gap-4 justify-self-center">
    <a href="https://github.com/bartoostveen">
      <Button class="cursor-pointer" variant="outline"><GitHubIcon /></Button>
    </a>
    <a href="mailto:bart@bartoostveen.nl" rel="nofollow">
      <Button class="cursor-pointer" variant="outline"><EmailIcon /></Button>
    </a>
    <a href="https://matrix.to/#/@bart:bartoostveen.nl">
      <Button class="cursor-pointer" variant="outline"><ChatIcon /></Button>
    </a>
  </div>

  <p class="lead">
    Hi, my name is Bart Oostveen. If you want to contact me, you should use one of the above links.
  </p>

  <p>
    You might be coming from ViTune, in that case, if you want to contact me, use

    <a href="mailto:development@vitune.app" rel="nofollow">
      <Button class="cursor-pointer" variant="outline"><EmailIcon />this email</Button>
    </a>

    instead.
  </p>
</main>

<div class="fixed top-0 justify-self-end p-4">
  <DarkModeToggle />
</div>
