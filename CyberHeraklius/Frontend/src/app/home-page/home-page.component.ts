import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-home-page',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './home-page.component.html',
  styleUrl: './home-page.component.css'
})

export class HomePageComponent {
  projectID: string = '1';
  componentID: string = '1.1';
  
  constructor(private router: Router, private route: ActivatedRoute) { console.log('Home-Page'); }
  
  onSubmit() {
    console.log('projectID:', this.projectID);
    console.log('componentID:', this.componentID);
    console.log('To Network-View');
    this.router.navigate(['/network-view', this.projectID, this.componentID]);
  }
}
