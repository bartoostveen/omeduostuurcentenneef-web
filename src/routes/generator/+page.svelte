<script lang="ts">
  import Button from "$lib/components/ui/button/button.svelte";
  import PlusIcon from "@lucide/svelte/icons/plus";
  import DeleteIcon from "@lucide/svelte/icons/trash";
  import CopyIcon from "@lucide/svelte/icons/copy";
  import DarkModeToggle from "../../components/DarkModeToggle.svelte";
  import { Input } from "$lib/components/ui/input";
  import { DatePicker } from "$lib/components/datepicker";
  import { decamel, filters, unix, type AppliedFilter } from "$lib/types";
  import { toast } from "svelte-sonner";

  let url = $state("");
  const appliedFilters = $state([]) as AppliedFilter[];

  const generatedUrl = $derived(() => {
    const filterQuery = appliedFilters
      .map(
        (filter) =>
          `${filter.not ? "!" : ""}${filter.name}=${filter.args.map(encodeURIComponent).join(",")}`
      )
      .join("&");
    return `https://calendarthing.omeduostuurcentenneef.nl/?url=${url}&${filterQuery}`;
  });
</script>

<main
  class="prose justify-self-center-safe p-2 py-12 prose-zinc md:prose-lg lg:prose-xl dark:prose-invert"
>
  <h1>calendarthing url generator</h1>

  <p>
    This is officially the worst url generator you have ever seen, but it works and I don't want to
    style this.
  </p>

  <label>
    Input url
    <Input type="text" placeholder="input url" class="max-w-ws" bind:value={url} />
  </label>

  <label for="url">Generated url:</label>
  <div class="flex gap-2">
    <Input
      id="url"
      type="text"
      placeholder="url"
      class="max-w-ws"
      disabled
      value={generatedUrl()}
    />
    <Button
      onclick={() => {
        window.navigator.clipboard.writeText(generatedUrl());
        toast.success("Copied to clipboard");
      }}
      variant="outline"
    >
      <CopyIcon />
    </Button>
  </div>

  <br />

  <div class="flex flex-wrap gap-2">
    {#each Object.entries(filters) as [, filter] (filter.name)}
      <Button
        class="cursor-pointer"
        variant="outline"
        onclick={() => {
          appliedFilters.push({
            name: filter.name,
            args: [],
            not: false
          });
        }}
      >
        <PlusIcon />
        {filter.name}
        <div class="text-gray-500">({filter.args.join(", ")})</div>
      </Button>
    {/each}
  </div>

  <br />

  <div class="not-prose flex flex-col gap-2">
    {#each appliedFilters as appliedFilter, i (i)}
      <div class="flex items-center gap-4">
        <input
          type="checkbox"
          value={appliedFilter.not}
          onchange={() => {
            appliedFilter.not = !appliedFilter.not;
          }}
        />

        <span class="align-middle">
          {appliedFilter.not ? "!" : ""}{decamel(appliedFilter.name).join(" ")}
        </span>

        <div class="flex items-center gap-2">
          {#each filters[appliedFilter.name]!.args as arg, j (j)}
            {#if arg.includes("date")}
              <DatePicker
                onValueUpdate={(dateValue) =>
                  (appliedFilter.args[j] = dateValue ? unix(dateValue).toString() : "")}
              />
            {:else}
              <Input
                type="text"
                placeholder={arg}
                value={appliedFilter.args[j] ?? ""}
                oninput={(event) => {
                  appliedFilters[i].args[j] = event.currentTarget.value;
                }}
              />
            {/if}
          {/each}
        </div>

        <div>
          <Button
            class="justify-self-end"
            onclick={() => {
              toast.success(`Deleted ${appliedFilter.name}`);
              appliedFilters.splice(i, 1);
            }}
            variant="outline"
          >
            <DeleteIcon />
          </Button>
        </div>
      </div>
    {/each}
  </div>
</main>

<div class="fixed top-0 justify-self-end p-4">
  <DarkModeToggle />
</div>
