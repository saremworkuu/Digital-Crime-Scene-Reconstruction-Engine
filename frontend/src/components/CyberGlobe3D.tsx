import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';

interface CyberGlobe3DProps {
  mode?: 'default' | 'advanced';
  onNodeClick?: (nodeName: string) => void;
  className?: string;
}

export const CyberGlobe3D: React.FC<CyberGlobe3DProps> = ({
  mode = 'default',
  onNodeClick,
  className = ''
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [isInteracting, setIsInteracting] = useState(false);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const width = container.clientWidth || 600;
    const height = container.clientHeight || 500;

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.2;
    container.replaceChildren(renderer.domElement);

    const globeGroup = new THREE.Group();
    scene.add(globeGroup);

    // 2. Base Wireframe Icosahedron (Geodesic cyber mesh)
    const detail = mode === 'advanced' ? 4 : 3;
    const sphereRadius = 66;
    const icoGeometry = new THREE.IcosahedronGeometry(sphereRadius, detail);

    // Fit camera dynamically to avoid clipping on any resolution
    const fitCameraToSphere = (w: number, h: number) => {
      const safeW = Math.max(10, w);
      const safeH = Math.max(10, h);
      const aspect = safeW / safeH;
      const vFovRad = (camera.fov * Math.PI) / 180;
      const targetBound = sphereRadius * 1.42;
      const distHeight = targetBound / Math.tan(vFovRad / 2);
      const distWidth = targetBound / (Math.tan(vFovRad / 2) * aspect);
      camera.position.z = Math.max(distHeight, distWidth) * 1.26;
      camera.aspect = aspect;
      camera.updateProjectionMatrix();
      renderer.setSize(safeW, safeH);
    };

    fitCameraToSphere(width, height);
    
    // Wireframe material with vibrant cyber-orange
    const wireframeMaterial = new THREE.MeshBasicMaterial({
      color: 0xff461e,
      wireframe: true,
      transparent: true,
      opacity: mode === 'advanced' ? 0.38 : 0.28,
    });
    const wireframeMesh = new THREE.Mesh(icoGeometry, wireframeMaterial);
    globeGroup.add(wireframeMesh);

    // 3. Glowing Node Particles at Vertices
    const vertices = icoGeometry.attributes.position.array;
    const nodeCount = vertices.length / 3;
    
    const nodeGeometry = new THREE.BufferGeometry();
    nodeGeometry.setAttribute('position', icoGeometry.attributes.position);

    // Vertex colors: accent points
    const colors = new Float32Array(nodeCount * 3);
    for (let i = 0; i < nodeCount; i++) {
      const isSpecial = i % 7 === 0;
      if (isSpecial) {
        colors[i * 3] = 1.0; // R
        colors[i * 3 + 1] = 0.55; // G (hot amber)
        colors[i * 3 + 2] = 0.15; // B
      } else {
        colors[i * 3] = 1.0; // R (vibrant orange)
        colors[i * 3 + 1] = 0.27; // G
        colors[i * 3 + 2] = 0.12; // B
      }
    }
    nodeGeometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    // Particle sprite texture created on canvas
    const canvas = document.createElement('canvas');
    canvas.width = 64;
    canvas.height = 64;
    const ctx = canvas.getContext('2d');
    if (ctx) {
      const gradient = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
      gradient.addColorStop(0, 'rgba(255, 255, 255, 1)');
      gradient.addColorStop(0.3, 'rgba(255, 110, 40, 0.85)');
      gradient.addColorStop(0.7, 'rgba(255, 70, 30, 0.3)');
      gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 0, 64, 64);
    }
    const particleTexture = new THREE.CanvasTexture(canvas);

    const nodeMaterial = new THREE.PointsMaterial({
      size: mode === 'advanced' ? 4.2 : 3.8,
      vertexColors: true,
      map: particleTexture,
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const nodePoints = new THREE.Points(nodeGeometry, nodeMaterial);
    globeGroup.add(nodePoints);

    // 4. Latitude/Longitude Rings
    const ringCount = 5;
    for (let r = 0; r < ringCount; r++) {
      const yOffset = (r - (ringCount - 1) / 2) * 26;
      const radiusAtY = Math.sqrt(Math.max(0, sphereRadius * sphereRadius - yOffset * yOffset));
      if (radiusAtY > 10) {
        const ringGeo = new THREE.RingGeometry(radiusAtY - 0.3, radiusAtY + 0.3, 64);
        const ringMat = new THREE.MeshBasicMaterial({
          color: 0xff5722,
          transparent: true,
          opacity: 0.15,
          side: THREE.DoubleSide
        });
        const ringMesh = new THREE.Mesh(ringGeo, ringMat);
        ringMesh.position.y = yOffset;
        ringMesh.rotation.x = Math.PI / 2;
        globeGroup.add(ringMesh);
      }
    }

    // 5. Attack Arcs (Curves between distant points)
    const arcGroup = new THREE.Group();
    globeGroup.add(arcGroup);

    const keySites = [
      { name: 'DC01.corp (Target Host)', vec: new THREE.Vector3(50, 45, 40).normalize().multiplyScalar(sphereRadius) },
      { name: '198.51.100.23 (Attacker C2)', vec: new THREE.Vector3(-60, 20, 45).normalize().multiplyScalar(sphereRadius) },
      { name: '10.0.1.10 (Pivot DMZ)', vec: new THREE.Vector3(-20, -50, 50).normalize().multiplyScalar(sphereRadius) },
      { name: '10.0.3.50 (Database Tier)', vec: new THREE.Vector3(45, -30, -50).normalize().multiplyScalar(sphereRadius) },
      { name: 'Egress TLS Proxy (Exfil)', vec: new THREE.Vector3(-30, 60, -35).normalize().multiplyScalar(sphereRadius) },
    ];

    // Create curved lines between key sites
    for (let i = 0; i < keySites.length; i++) {
      const start = keySites[i].vec;
      const end = keySites[(i + 1) % keySites.length].vec;

      const mid = start.clone().add(end).multiplyScalar(0.5);
      const arcAltitude = sphereRadius * (1.25 + (i % 2) * 0.15);
      mid.normalize().multiplyScalar(arcAltitude);

      const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
      const points = curve.getPoints(50);
      const curveGeo = new THREE.BufferGeometry().setFromPoints(points);

      const curveMat = new THREE.LineBasicMaterial({
        color: i === 0 ? 0xff3b10 : 0xff7b22,
        transparent: true,
        opacity: 0.65,
        linewidth: 2
      });

      const arcLine = new THREE.Line(curveGeo, curveMat);
      arcGroup.add(arcLine);

      // Add prominent beacon dot
      const beaconGeo = new THREE.SphereGeometry(2.5, 16, 16);
      const beaconMat = new THREE.MeshBasicMaterial({
        color: i === 0 ? 0xff1e00 : 0xff9900
      });
      const beacon = new THREE.Mesh(beaconGeo, beaconMat);
      beacon.position.copy(start);
      globeGroup.add(beacon);
    }

    // 6. Ambient Outer Particle Cloud
    const starCount = 180;
    const starGeo = new THREE.BufferGeometry();
    const starPositions = new Float32Array(starCount * 3);
    for (let s = 0; s < starCount; s++) {
      const u = Math.random();
      const v = Math.random();
      const theta = u * 2.0 * Math.PI;
      const phi = Math.acos(2.0 * v - 1.0);
      const r = sphereRadius * (1.1 + Math.random() * 0.8);
      const sinPhi = Math.sin(phi);
      starPositions[s * 3] = r * sinPhi * Math.cos(theta);
      starPositions[s * 3 + 1] = r * sinPhi * Math.sin(theta);
      starPositions[s * 3 + 2] = r * Math.cos(phi);
    }
    starGeo.setAttribute('position', new THREE.BufferAttribute(starPositions, 3));
    const starMat = new THREE.PointsMaterial({
      size: 2.2,
      color: 0xff6622,
      transparent: true,
      opacity: 0.45,
      blending: THREE.AdditiveBlending
    });
    const starField = new THREE.Points(starGeo, starMat);
    scene.add(starField);

    // Initial slight tilt
    globeGroup.rotation.x = 0.22;
    globeGroup.rotation.y = -0.45;

    // 7. Interaction Handlers (Drag to Rotate)
    let isDragging = false;
    let previousMousePosition = { x: 0, y: 0 };
    let targetRotationX = 0.22;
    let targetRotationY = -0.45;

    const onMouseDown = (e: MouseEvent) => {
      isDragging = true;
      setIsInteracting(true);
      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    const onMouseMove = (e: MouseEvent) => {
      if (!isDragging) return;
      const deltaX = e.clientX - previousMousePosition.x;
      const deltaY = e.clientY - previousMousePosition.y;

      targetRotationY += deltaX * 0.006;
      targetRotationX += deltaY * 0.006;

      // Clamp vertical rotation
      targetRotationX = Math.max(-Math.PI / 2.5, Math.min(Math.PI / 2.5, targetRotationX));

      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    const onMouseUp = () => {
      isDragging = false;
      setTimeout(() => setIsInteracting(false), 500);
    };

    const domElement = renderer.domElement;
    domElement.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);

    // 8. Animation Loop
    let animationFrameId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Smooth inertia rotation
      globeGroup.rotation.y += (targetRotationY - globeGroup.rotation.y) * 0.08;
      globeGroup.rotation.x += (targetRotationX - globeGroup.rotation.x) * 0.08;

      // Subtle idle auto-rotation if user is not actively dragging
      if (!isDragging) {
        targetRotationY += 0.0018;
      }

      // Pulse particle size slightly
      nodeMaterial.size = (mode === 'advanced' ? 4.2 : 3.8) + Math.sin(elapsedTime * 2.5) * 0.4;

      // Slow drift of starfield
      starField.rotation.y = elapsedTime * 0.02;

      renderer.render(scene, camera);
    };

    animate();

    // 9. Resize Observer
    const handleResize = () => {
      if (!container) return;
      const newWidth = container.clientWidth || 600;
      const newHeight = container.clientHeight || 500;
      fitCameraToSphere(newWidth, newHeight);
    };

    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(container);

    return () => {
      cancelAnimationFrame(animationFrameId);
      resizeObserver.disconnect();
      domElement.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      renderer.dispose();
      icoGeometry.dispose();
      wireframeMaterial.dispose();
      nodeGeometry.dispose();
      nodeMaterial.dispose();
      starGeo.dispose();
      starMat.dispose();
      particleTexture.dispose();
    };
  }, [mode]);

  return (
    <div className={`relative w-full h-full min-h-[380px] flex items-center justify-center select-none ${className}`}>
      {/* 3D Canvas Mount Point */}
      <div 
        ref={containerRef} 
        className="w-full h-full cursor-grab active:cursor-grabbing flex items-center justify-center overflow-hidden" 
      />

      {/* Floating Cyber Ambient Glow */}
      <div 
        className="pointer-events-none absolute inset-0 flex items-center justify-center opacity-60"
        style={{
          background: 'radial-gradient(circle at center, rgba(255, 70, 30, 0.16) 0%, rgba(255, 70, 30, 0.04) 40%, transparent 70%)'
        }}
      />

      {/* Drag & Rotate Indicator Overlay */}
      <div className="pointer-events-none absolute bottom-3 left-1/2 -translate-x-1/2 px-3 py-1 rounded-full bg-neutral-900/80 border border-neutral-800 text-[10px] text-neutral-400 font-mono tracking-wider backdrop-blur-md flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-[#ff461e] animate-pulse" />
        <span>INTERACTIVE 3D ATTACK MESH · DRAG TO ROTATE</span>
      </div>
    </div>
  );
};
