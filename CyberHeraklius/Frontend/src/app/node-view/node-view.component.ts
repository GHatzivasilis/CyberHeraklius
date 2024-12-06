import { Component, inject, OnInit } from '@angular/core';
import { DataService } from '../http-service.service';
import { CommonModule } from '@angular/common';
import { Router, ActivatedRoute } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { environment } from '../environments/environment';

@Component({
  selector: 'app-node-view',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './node-view.component.html',
  styleUrl: './node-view.component.css'
})
export class NodeViewComponent implements OnInit {
  //node_data: any;
  isLoading = false;
  projectID: string = '1';
  componentID: string = '1.1';
  IP: string = '45.33.32.156'; //127.0.0.1
  node_data: any;
  /*node_data: any = {
  IP: '45.33.32.156',
  projectID: '1',
  componentID: '1.1',
  results: [
    [
      80,
      'open',
      'http',
      'tcp',
      'Apache httpd',
      '2.4.7',
      '(Ubuntu)',
      'cpe:/a:apache:http_server:2.4.7'
    ],
    [ 81, 'filtered', 'hosts2-ns', 'tcp', '', '', '', '' ]
  ]
};*/
  
  
  constructor(private dataService: DataService, private router: Router, private route: ActivatedRoute) { console.log('Node-View'); }
  
  ngOnInit(): void {
    console.log('Node-View-ngOnInit');
    	// Read Input parameters -- projectID, componentID, IP
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
    this.IP = '45.33.32.156';
    if(tmp!=null) {
      	this.IP=tmp;
    }
    
    	// Subscribe to changes for projectID and IP
    this.route.params.subscribe((data) => {

    });
    this.route.params.subscribe(params => {this.projectID = params['projectID'];});
    this.route.params.subscribe(params => {this.IP = params['IP'];});
    
    	// Print Node details
    this.getnode_view();
  }
  
  getnode_view(): void {
    const url = environment.apiUrl+'/network_mapping/getnodeports?projectID='+this.projectID+'&componentID='+this.componentID+'&IP='+this.IP;
    this.dataService.getData(url).subscribe({
      next: (response) => {
        this.node_data = response;
      },
      error: (err) => console.error('Error fetching data:', err)
    });
  }
  
  navigateToNetworkView() {
    console.log('To Network-View');
    this.router.navigate(['/network-view', this.projectID, this.componentID]);
  }
  
  updateNode(index: number) {
    const url = environment.apiUrl+'/network_mapping/updatenodeports?projectID='+this.projectID+'&componentID='+this.componentID+'&IP='+this.IP+'&port='+this.node_data.results[index][0]+'&name='+this.node_data.results[index][2]+'&product='+this.node_data.results[index][4]+'&version='+this.node_data.results[index][5]+'&cpeID='+this.node_data.results[index][7];
    this.dataService.getData(url).subscribe({
      next: (response) => {
        console.log('Update Node result', response);
      },
      error: (err) => console.error('Error fetching data:', err)
    });
  }
  
  ctiSearch(index: number) {
    this.isLoading = true; // Start loading
    const url = environment.apiUrl+'/cti_search?projectID='+this.projectID+'&componentID='+this.componentID+'&cpeID='+this.node_data.results[index][7];
    console.log('CTI Search - Index: ', index);
    this.dataService.getData(url).subscribe({
      next: (response) => {
        console.log('CTI Search');
        this.isLoading = false; // Stop loading
        this.navigateToNetworkView();
      },
      error: (err) => console.error('Error fetching data:', err)
    });
  }
  
}
