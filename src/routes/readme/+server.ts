import { error, type RequestHandler } from "@sveltejs/kit";
import { env } from "$env/dynamic/private";

let lastFetched = 0;
let response: Blob | null = null;
const dt = 30 * 60 * 1000;

export const GET: RequestHandler = async () => {
  const endpoint = env.GH_README_STATS_ENDPOINT;
  if (!endpoint) {
    error(500, "Server is not capable of generating readme");
  }
  if (response && (lastFetched + dt) <= Date.now()) {
    return new Response(response);
  }
  try {
    const newResponse = await (await fetch(endpoint)).blob();
    lastFetched = Date.now();
    response = newResponse;
    return new Response(newResponse);
  } catch (e) {
    console.error("Failed to generate readme", e);
    error(500, "Server cannot generate readme at this moment");
  }
};
