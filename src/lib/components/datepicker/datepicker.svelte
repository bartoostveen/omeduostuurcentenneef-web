<script lang="ts">
  import CalendarIcon from "@lucide/svelte/icons/calendar";
  import { type DateValue, DateFormatter, getLocalTimeZone } from "@internationalized/date";
  import { cn } from "$lib/utils.js";
  import { Button } from "$lib/components/ui/button/index.js";
  import { Calendar } from "$lib/components/ui/calendar";
  import * as Popover from "$lib/components/ui/popover";

  const df = new DateFormatter("en-US", {
    dateStyle: "long"
  });

  let value = $state<DateValue>();
  const { onValueUpdate } = $props<{ onValueUpdate: (arg0: DateValue) => void }>();

  $effect(() => {
    onValueUpdate(value);
  });
</script>

<Popover.Root>
  <Popover.Trigger>
    {#snippet child({ props })}
      <Button
        variant="outline"
        class={cn("w-70 justify-start text-left font-normal", !value && "text-muted-foreground")}
        {...props}
      >
        <CalendarIcon class="mr-2 size-4" />
        {value ? df.format(value.toDate(getLocalTimeZone())) : "Select a date"}
      </Button>
    {/snippet}
  </Popover.Trigger>
  <Popover.Content class="w-auto p-0">
    <Calendar bind:value type="single" initialFocus />
  </Popover.Content>
</Popover.Root>
