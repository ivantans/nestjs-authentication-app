export type BaseResponseApi<T> = {
  statusCode: number
  statusMessage: string
  data?: T
}