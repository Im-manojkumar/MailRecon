declare module 'react-cytoscapejs' {
  import { Component } from 'react';
  import cytoscape from 'cytoscape';

  export interface CytoscapeComponentProps {
    id?: string;
    cy?: (cy: cytoscape.Core) => void;
    style?: React.CSSProperties;
    elements: any[];
    layout?: any;
    stylesheet?: any;
    className?: string;
    wheelSensitivity?: number;
    pan?: { x: number; y: number };
    zoom?: number;
    zoomingEnabled?: boolean;
    userZoomingEnabled?: boolean;
    panningEnabled?: boolean;
    userPanningEnabled?: boolean;
    boxSelectionEnabled?: boolean;
    autoungrabify?: boolean;
    autounselectify?: boolean;
  }

  export default class CytoscapeComponent extends Component<CytoscapeComponentProps> {}
}
