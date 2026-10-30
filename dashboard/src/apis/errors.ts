/** Raised when the session is missing or expired; the UI sends the user to /login. */
export class UnauthorizedError extends Error {
  constructor() {
    super('session expired, please log in again')
  }
}

/** A request the server rejected (4xx) or that failed local validation. */
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message)
  }
}
