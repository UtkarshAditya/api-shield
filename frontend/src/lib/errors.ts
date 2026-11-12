import { ContractError, HttpError } from "@/api/client";

/** Plain-English message for a failed call. Gateway problems get their own wording, because
 * the Admin API saves nothing when the gateway cannot be reached. */
export function describeError(err: unknown): string {
  if (err instanceof HttpError) {
    switch (err.code) {
      case "gateway_unreachable":
        return "The gateway is not reachable, so nothing was changed. Check that the gateway is running, then try again.";
      case "gateway_auth_failed":
        return "The gateway refused the Admin API's credentials, so nothing was changed. The admin token on both sides must match.";
      case "gateway_not_configured":
        return "No gateway is configured for the Admin API, so nothing was changed.";
      case "forbidden":
        return "Your role cannot do this.";
      default:
        return err.message || `Request failed (${err.status}).`;
    }
  }
  if (err instanceof ContractError) return `The server answered in an unexpected format. ${err.message}`;
  if (err instanceof TypeError) return "Could not reach the Admin API. Check your connection and try again.";
  return "Something went wrong. Try again.";
}
