import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule } from '@angular/common/http'; // Import HttpClientModule
import { AppComponent } from './app.component';
//import { AppRoutingModule } from './app-routing.module';
import { AppRoutingModule } from './app.routes';
import { FormsModule } from '@angular/forms';
import { NgxEchartsModule } from 'ngx-echarts';
//import { AppRoutingModule } from './app-routing.module';
//import * as echarts from 'echarts';


// Import ECharts modules manually to reduce bundle size
import * as echarts from 'echarts/core';
import {
  PieChart,
  LineChart // Add other chart types as needed
} from 'echarts/charts';
import {
  TooltipComponent,
  LegendComponent
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

echarts.use([
  PieChart,
  LineChart,
  TooltipComponent,
  LegendComponent,
  CanvasRenderer
]);

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    HttpClientModule,
    NgxEchartsModule.forRoot({
      echarts,
    }),
  ],
  providers: [HttpClientModule],
  bootstrap: [AppComponent, DataDisplayComponent, IPInputComponent]
})
export class AppModule { }
