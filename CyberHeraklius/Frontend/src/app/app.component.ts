import { Component } from '@angular/core';
//import { Component, OnInit } from '@angular/core';
import { RouterModule, RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { DataDisplayComponent } from './network-view/network-view.component';
import { NodeViewComponent } from './node-view/node-view.component';
import { ExploitViewComponent } from './exploit-view/exploit-view.component';
import { IPInputComponent } from './ip-input/ip-input.component';
import { HomePageComponent } from './home-page/home-page.component';
import { DataService } from './http-service.service';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterModule, RouterOutlet, RouterLink, RouterLinkActive, DataDisplayComponent, ExploitViewComponent, IPInputComponent, NodeViewComponent, HomePageComponent],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  title = 'network-assessment';
  constructor() { console.log('AppComponent'); }
  
}
