export {}

declare global {
  namespace Express {
    interface User {
      uuid: string
      email: string
    }
  }
}