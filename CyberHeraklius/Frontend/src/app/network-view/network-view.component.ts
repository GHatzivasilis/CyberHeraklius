import { Component, inject, OnInit, OnDestroy } from '@angular/core';
import { DataService } from '../http-service.service';
import { CommonModule } from '@angular/common';
import { NgxEchartsModule } from 'ngx-echarts';
import { EChartsOption } from 'echarts';
import * as echarts from 'echarts';
import { RouterModule, RouterLink, Router, ActivatedRoute } from '@angular/router';
import { ExploitViewComponent } from '../exploit-view/exploit-view.component';
import { IPInputComponent } from '../ip-input/ip-input.component';
import { Subscription } from 'rxjs';
import { environment } from '../environments/environment';

@Component({
  selector: 'app-network-view',
  standalone: true,
  imports: [RouterModule, RouterLink, CommonModule, NgxEchartsModule, ExploitViewComponent, IPInputComponent],
  templateUrl: './network-view.component.html',
  styleUrls: ['./network-view.component.css'],
})
export class DataDisplayComponent implements OnInit {
  data: any;
  isLoading = false;
  
  openports: number = 0;
  filteredports: number = 0;
  closedports: number = 0;
  totalnodes: number = 0;
  
  risk: number = 0;
  cveLow: number = 0;
  cveMed: number = 0;
  cveHigh: number = 0;
  cveCritical: number = 0;
  
  cweLow: number = 0;
  cweMed: number = 0;
  cweHigh: number = 0;  
  cweCritical: number = 0;
  
  capecLow: number = 0;
  capecMed: number = 0;
  capecHigh: number = 0;
  capecCritical: number = 0;
  
  exploitLow: number = 0;
  exploitMed: number = 0;
  exploitHigh: number = 0;
  exploitCritical: number = 0;
  
  projectID: string = '1';
  componentID: string = '1.1';
  paramsSubscription : Subscription;
  
  chartDom: any;
  myChart: any;
  option: any;
  
  constructor(private dataService: DataService, private router: Router, private route: ActivatedRoute) { console.log('Network-View');
  this.paramsSubscription = this.route.paramMap.subscribe(params => {
      var tmp = params.get('projectID');
      this.projectID = '1';
      if(tmp!=null) {
      	this.projectID=tmp;
      }
      //this.hosts_overview();
      //this.getnodes_view();
    });
    this.route.params.subscribe(params => {this.projectID = params['projectID'];});
  }
  
  ngOnInit(): void {
    console.log('Network-View-ngOnInit');
    this.paramsSubscription = this.route.paramMap.subscribe(params => {
      var tmp = params.get('projectID');
      this.projectID = '1';
      if(tmp!=null) {
      	this.projectID=tmp;
      }
      tmp = params.get('componentID');
      this.componentID = '1.1';
      if(tmp!=null) {
      	this.componentID=tmp;
      }
      this.assessment_overview();
      this.hosts_overview();
      this.getnodes_view();
    });
    
  }
  
  ngOnDestroy() {
    console.log("Component will be destroyed");
    this.paramsSubscription.unsubscribe();
  }
  
  assessment_overview(): void {
    const totalAssessmentURL = environment.apiUrl+'/cti_search/getOverview?projectID='+this.projectID+'&componentID='+this.componentID;
    
     this.dataService.getData(totalAssessmentURL).subscribe({
      next: (response) => {
        //var result = response.results;
        //console.log('Response (network_assessment_overview):', result);
        this.risk = response.risk;
        this.cveLow = response.cveLow;
        this.cveMed = response.cveMed;
        this.cveHigh = response.cveHigh;
        this.cveCritical = response.cveCritical;
        
        this.cweLow = response.cweLow;
        this.cweMed = response.cweMed;
        this.cweHigh = response.cweHigh;
        this.cweCritical = response.cweCritical;
  
        this.capecLow = response.capecLow;
        this.capecMed = response.capecMed;
        this.capecHigh = response.capecHigh;
        this.capecCritical = response.capecCritical;
        
        this.exploitLow = response.exploitLow;
        this.exploitMed = response.exploitMed;
        this.exploitHigh = response.exploitHigh;
        this.exploitCritical = response.exploitCritical;
        
        this.print_assessment_chart();
      },
      error: (err) => console.error('Error fetching data:', err)
      });
    
  }
  
  hosts_overview(): void {
    const totalNodesURL = environment.apiUrl+'/network_mapping/getnodesnum?projectID='+this.projectID+'&componentID='+this.componentID;
    const openPortsUrl = environment.apiUrl+'/network_mapping/getopenportsnum?projectID='+this.projectID+'&componentID='+this.componentID;
    const filteredPortsUrl = environment.apiUrl+'/network_mapping/getfilteredportsnum?projectID='+this.projectID+'&componentID='+this.componentID;
    
    
    this.dataService.getData(openPortsUrl).subscribe({
      next: (response) => {
        this.openports = response.results;
        //console.log('Response (openports):', this.openports);
        
        this.dataService.getData(filteredPortsUrl).subscribe({
	      next: (response) => {
		this.filteredports = response.results;
		//console.log('Response (filteredports):', this.filteredports);
		this.print_chart();
		
		this.dataService.getData(totalNodesURL).subscribe({
			next: (response) => {
				this.totalnodes = response.results;
				//console.log('Response (totalnodes):', this.totalnodes);
			},
			error: (err) => console.error('Error fetching data:', err)
		});
	      },
	      error: (err) => console.error('Error fetching data:', err)
	    });
        
        //this.print_chart();
      },
      error: (err) => console.error('Error fetching data:', err)
    });
    /*this.dataService.getData(filteredPortsUrl).subscribe({
      next: (response) => {
        this.filteredports = response.results;
        console.log('Response (filteredports):', this.filteredports);
        this.print_chart();
      },
      error: (err) => console.error('Error fetching data:', err)
    });*/
  }
  
  print_assessment_chart(): void {
    if (typeof document !== 'undefined') {
	    //console.log('DOCUMENT');
	    // will run in client's browser only
	    this.chartDom = document.getElementById('assessment_chart');
	    this.myChart = echarts.init(this.chartDom);
	    
	    // This example requires ECharts v5.5.0 or later
	    this.option = {
		  tooltip: {
		    trigger: 'axis',
		    axisPointer: {
		      // Use axis to trigger tooltip
		      type: 'shadow' // 'shadow' as default; can also be 'line' or 'shadow'
		    }
		  },
		  legend: {},
		  grid: {
		    left: '3%',
		    right: '4%',
		    bottom: '3%',
		    containLabel: true
		  },
		  xAxis: {
		    type: 'value'
		  },
		  yAxis: {
		    type: 'category',
		    data: ['Vulnerabilities', 'Weaknesses', 'Threats', 'Exploits']
		  },
		  series: [
		    {
		      name: 'Low',
		      type: 'bar',
		      stack: 'total',
		      label: {
			show: true
		      },
		      emphasis: {
			focus: 'series'
		      },
		      data: [this.cveLow, this.cweLow, this.capecLow, this.exploitLow]
		    },
		    {
		      name: 'Medium',
		      type: 'bar',
		      stack: 'total',
		      label: {
			show: true
		      },
		      emphasis: {
			focus: 'series'
		      },
		      data: [this.cveMed, this.cweMed, this.capecMed, this.exploitMed]
		    },
		    {
		      name: 'High',
		      type: 'bar',
		      stack: 'total',
		      label: {
			show: true
		      },
		      emphasis: {
			focus: 'series'
		      },
		      data: [this.cveHigh, this.cweHigh, this.capecHigh, this.exploitHigh]
		    },
		    {
		      name: 'Critical',
		      type: 'bar',
		      stack: 'total',
		      label: {
			show: true
		      },
		      emphasis: {
			focus: 'series'
		      },
		      data: [this.cveCritical, this.cweCritical, this.capecCritical, this.exploitCritical]
		    }
		  ]
		};
	    this.myChart.setOption(this.option, {
		    notMerge: false,
		    replaceMerge: ['series', 'legend', 'tooltip'],
		    lazyUpdate: true
		  });
	    //this.myChart.resize();
    }
  }
  
  print_chart(): void {
    if (typeof document !== 'undefined') {
	    //console.log('DOCUMENT');
	    // will run in client's browser only
	    this.chartDom = document.getElementById('main');
	    this.myChart = echarts.init(this.chartDom);
	    
	    // This example requires ECharts v5.5.0 or later
	    this.option = {
		  tooltip: {
		    trigger: 'item'
		  },
		  legend: {
		    top: '5%',
		    left: 'center'
		  },
		  series: [
		    {
		      name: 'Access From',
		      type: 'pie',
		      radius: ['40%', '70%'],
		      center: ['50%', '70%'],
		      // adjust the start and end angle
		      startAngle: 180,
		      endAngle: 360,
		      data: [
			{ value: this.openports, name: 'Open' },
			{ value: this.filteredports, name: 'Filtered' }
		      ]
		    }
		  ],
	    };
	    this.myChart.setOption(this.option, {
		    notMerge: false,
		    replaceMerge: ['series', 'legend', 'tooltip'],
		    lazyUpdate: true
		  });
	    //this.myChart.resize();
    }
  }
  
  getnodes_view(): void {
    const url = environment.apiUrl+'/network_mapping/getnodes?projectID='+this.projectID+'&componentID='+this.componentID;;
    this.dataService.getData(url).subscribe({
      next: (response) => {
        this.data = response;
      },
      error: (err) => console.error('Error fetching data:', err)
    });
  }
  
  navigateToNodeView(projectID2: string, IP: String) {
    console.log('To Node-View');
    this.router.navigate(['/node-view', this.projectID, this.componentID, IP]);
  }
  
  netAssessment(index: number) {
    this.isLoading = true; // Start loading
    const url = environment.apiUrl+'/network_assessment?projectID='+this.projectID+'&componentID='+this.componentID+'&ip='+this.data.results[index][1];
    console.log('Network Assessment - Index: ', index);
    this.dataService.getData(url).subscribe({
      next: (response) => {
        console.log('SecOPERA Network Assessment');
        this.isLoading = false; // Stop loading
        this.navigateToNetworkView();
      },
      error: (err) => console.error('Error fetching data:', err)
    });
  }
  
  navigateToHomePage() {
    console.log('To Home-Page');
    this.router.navigate(['/select-project', ""]);
  }
  
  navigateToNetworkView() {
    console.log('To Network-View');
    //this.router.navigate(['/network-view', this.projectID, this.componentID]);
    window.location.reload();
  }
}
