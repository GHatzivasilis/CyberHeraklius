import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { DataDisplayComponent } from './network-view/network-view.component';
import { NodeViewComponent } from './node-view/node-view.component';
import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: '/network-view', pathMatch: 'full' },
  { path: 'network-view', component: DataDisplayComponent },
  { path: 'node-view/:projectID/:IP', component: NodeViewComponent }
];

@NgModule({
  imports: [RouterModule.forRoot(routes, {onSameUrlNavigation: 'reload'})],
  exports: [RouterModule]
})
export class AppRoutingModule { }
