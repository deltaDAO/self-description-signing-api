import { Controller, Post, Res, Body, HttpStatus } from '@nestjs/common'
import { AppService } from './app.service'
import { Response } from 'express'

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post('/sign')
  async sign(@Body() selfDescription: any, @Res() response: Response) {
    try {
      const result = await this.appService.signSelfDescription(selfDescription.selfDescription)
      return response.status(HttpStatus.OK).send(result)
    } catch (error) {
      console.error(error)
      return response.status(HttpStatus.BAD_REQUEST).send(error)
    }
  }
}
