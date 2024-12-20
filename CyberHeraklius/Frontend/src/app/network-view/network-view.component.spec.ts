import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NetworkViewComponent } from './network-view.component';

describe('NetworkViewComponent', () => {
  let component: NetworkViewComponent;
  let fixture: ComponentFixture<NetworkViewComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [NetworkViewComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(NetworkViewComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
