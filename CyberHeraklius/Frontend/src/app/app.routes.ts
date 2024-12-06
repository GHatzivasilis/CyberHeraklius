import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { DataDisplayComponent } from './network-view/network-view.component';
import { NodeViewComponent } from './node-view/node-view.component';
import { IPInputComponent } from './ip-input/ip-input.component';
import { HomePageComponent } from './home-page/home-page.component';

export const routes: Routes = [
  { path: '', redirectTo: 'select-project/', pathMatch: 'full', title: 'Home Page' },
  { path: 'select-project/', component: HomePageComponent, title: 'Select Project' },
  { path: 'network-view/:projectID/:componentID', component: DataDisplayComponent, title: 'Network View' },
  { path: 'node-view/:projectID/:componentID/:IP', component: NodeViewComponent, title: 'Node View' },
  { path: 'scanip/:projectID/:componentID', component: IPInputComponent, title: 'Scan IP' },
  { path: 'scanip/:projectID/:componentID/:IP/:portRange', component: IPInputComponent, title: 'Scan IP' }
];

@NgModule({
  imports: [RouterModule.forRoot(routes, {onSameUrlNavigation: 'reload'})],
  exports: [RouterModule]
})
export class AppRoutingModule { }
