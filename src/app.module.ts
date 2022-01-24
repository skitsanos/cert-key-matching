import {Module} from '@nestjs/common';
import {AppController} from './app.controller';
import {AppService} from './app.service';
import {EchoModule} from './echo/echo.module';
import {UploadsModule} from './uploads/uploads.module';

@Module({
    imports: [
        EchoModule,
        UploadsModule
    ],
    controllers: [AppController],
    providers: [AppService]
})
export class AppModule
{
}
