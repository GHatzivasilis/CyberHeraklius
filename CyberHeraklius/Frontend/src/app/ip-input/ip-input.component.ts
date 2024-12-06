import { Component } from '@angular/core';
import { DataService } from '../http-service.service';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule, RouterLink, Router, ActivatedRoute } from '@angular/router';
import { environment } from '../environments/environment';

@Component({
  selector: 'app-ip-input',
  standalone: true,
  imports: [RouterModule, RouterLink, CommonModule,FormsModule],
  templateUrl: './ip-input.component.html',
  styleUrls: ['./ip-input.component.css']
})
export class IPInputComponent {
  projectID: string = '1';
  componentID: string = '1.1';
  ip: string = '127.0.0.1';
  portRange: string = '80-80';
  isLoading = false;
  response: any = null;

  constructor(private dataService: DataService, private router: Router, private route: ActivatedRoute) { 
    var tmp = this.route.snapshot.params['projectID'];
    this.projectID = '1';
    if(tmp!=null) {
      	this.projectID=tmp;
    }
    tmp = this.route.snapshot.params['componentID'];
    this.componentID = '1.1';
    if(tmp!=null) {
      	this.componentID=tmp;
    }
    tmp = this.route.snapshot.params['IP'];
    this.ip = '127.0.0.1';
    if(tmp!=null) {
      	this.ip=tmp;
    }
    tmp = this.route.snapshot.params['portRange'];
    this.portRange = '80-80';
    if(tmp!=null) {
      	this.portRange=tmp;
    }
  }
  //constructor(private http: HttpClient) {}
  
  onSubmit() {
    console.log('projectID:', this.projectID);
    console.log('componentID:', this.componentID);
    this.isLoading = true; // Start loading
    const url = environment.apiUrl+'/network_mapping?projectID='+this.projectID+'&componentID='+this.componentID+'&ip='+this.ip+"&ports="+this.portRange;  // Update this URL to your actual API endpoint
    this.dataService.getData(url).subscribe({
        next: (data) => {
          this.response = data;
          console.log('Response:', data);
          this.isLoading = false; // Stop loading
          this.navigateToNodeView();
        },
        error: (error) => {
          console.error('Error:', error);
        }
      });
      //this.navigateToNodeView();
  }
  
  navigateToNodeView(): void {
    console.log('To Node-View');
    this.router.navigate(['/node-view', this.projectID, this.componentID, this.ip]);
  }
}
