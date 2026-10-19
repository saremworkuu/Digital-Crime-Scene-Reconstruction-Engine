import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { useApp } from '../store';

export interface ThreatCityBeacon {
  id: string;
  name: string;
  country: string;
  lat: number;
  lon: number;
  count: number;
  severity: 'critical' | 'high' | 'medium';
}

export const MONITORED_BEACONS: ThreatCityBeacon[] = [
  { id: 'syd', name: 'Sydney', country: 'Australia', lat: -33.8688, lon: 151.2093, count: 72, severity: 'critical' },
  { id: 'nyc', name: 'New York', country: 'USA', lat: 40.7128, lon: -74.0060, count: 58, severity: 'high' },
  { id: 'sp', name: 'São Paulo', country: 'Brazil', lat: -23.5505, lon: -46.6333, count: 21, severity: 'medium' },
  { id: 'sg', name: 'Singapore', country: 'Singapore', lat: 1.3521, lon: 103.8198, count: 12, severity: 'medium' },
  { id: 'la', name: 'Los Angeles', country: 'USA', lat: 34.0522, lon: -118.2437, count: 4, severity: 'medium' },
  { id: 'mia', name: 'Miami', country: 'USA', lat: 25.7617, lon: -80.1918, count: 0.75, severity: 'medium' },
];

function latLonToVector(lat: number, lon: number, radius: number): THREE.Vector3 {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  const x = -(radius * Math.sin(phi) * Math.cos(theta));
  const z = radius * Math.sin(phi) * Math.sin(theta);
  const y = radius * Math.cos(phi);
  return new THREE.Vector3(x, y, z);
}

interface CyberThreatGlobeProps {
  className?: string;
  height?: number | string;
  interactive?: boolean;
  threatPointsCount?: number;
  mode?: 'default' | 'advanced';
  onModeChange?: (mode: 'default' | 'advanced') => void;
  showControls?: boolean;
  caption?: string;
  activeLocationId?: string;
  onLocationSelect?: (locationId: string) => void;
  sizeMultiplier?: number;
  speedMultiplier?: number;
}

export const CyberThreatGlobe: React.FC<CyberThreatGlobeProps> = ({
  className = '',
  height = 360,
  interactive = true,
  threatPointsCount = 48,
  mode: controlledMode,
  onModeChange,
  showControls = true,
  caption,
  activeLocationId,
  onLocationSelect,
  sizeMultiplier = 1.0,
  speedMultiplier = 1.0
}) => {
  const { theme } = useApp();
  const isLightMode = theme === 'light';

  const containerRef = useRef<HTMLDivElement>(null);
  const [internalMode, setInternalMode] = useState<'default' | 'advanced'>('default');
  const currentMode = controlledMode !== undefined ? controlledMode : internalMode;

  const targetRotationRef = useRef<{ x: number; y: number }>({ x: 0.2, y: -0.4 });
  const isDraggingRef = useRef(false);

  const setMode = (m: 'default' | 'advanced') => {
    setInternalMode(m);
    if (onModeChange) onModeChange(m);
  };

  // When activeLocationId changes, orient the globe smoothly to focus on it
  useEffect(() => {
    if (!activeLocationId) return;
    const found = MONITORED_BEACONS.find(b => b.id === activeLocationId);
    if (found) {
      const phi = (90 - found.lat) * (Math.PI / 180);
      const theta = (found.lon + 180) * (Math.PI / 180);
      targetRotationRef.current.y = -theta + Math.PI / 2;
      targetRotationRef.current.x = -(phi - Math.PI / 2) * 0.7;
    }
  }, [activeLocationId]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // 1. Scene setup
    const scene = new THREE.Scene();

    const initialWidth = container.clientWidth || 400;
    const initialHeight = typeof height === 'number' ? height : container.clientHeight || 360;

    const camera = new THREE.PerspectiveCamera(45, Math.max(0.2, initialWidth / initialHeight), 0.1, 1000);

    const renderer = new THREE.WebGLRenderer({
      alpha: true,
      antialias: true,
      powerPreference: 'high-performance'
    });
    renderer.setSize(initialWidth, initialHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x000000, 0);
    container.replaceChildren(renderer.domElement);

    // Root Group
    const globeGroup = new THREE.Group();
    scene.add(globeGroup);

    // Geodesic Icosahedron Wireframe
    // Set base radius to 1.85 * sizeMultiplier so the circle is prominent, bold, and larger
    const radius = 1.85 * sizeMultiplier;
    const detail = currentMode === 'advanced' ? 3 : 2;
    const icoGeometry = new THREE.IcosahedronGeometry(radius, detail);
    
    // Wireframe lines with cyber-orange color
    const wireframeGeometry = new THREE.WireframeGeometry(icoGeometry);
    const wireframeMaterial = new THREE.LineBasicMaterial({
      color: isLightMode ? 0xc2410c : 0xf95721,
      transparent: true,
      opacity: isLightMode ? 0.72 : (currentMode === 'advanced' ? 0.45 : 0.30),
      linewidth: 1
    });
    const wireframeLines = new THREE.LineSegments(wireframeGeometry, wireframeMaterial);
    globeGroup.add(wireframeLines);

    // Inner subtle glow core sphere - frosted translucent glass in light mode, deep obsidian in dark mode
    const coreGeo = new THREE.SphereGeometry(radius * 0.94, 32, 32);
    const coreMat = new THREE.MeshBasicMaterial({
      color: isLightMode ? 0xffffff : 0x120a06,
      transparent: true,
      opacity: isLightMode ? 0.15 : 0.55,
      wireframe: false
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    globeGroup.add(coreMesh);

    // Elegant 3D Cyber Equatorial & Coordinate Rings (smooth toruses instead of flat plates)
    const ringGroup = new THREE.Group();
    globeGroup.add(ringGroup);

    const eqGeo = new THREE.TorusGeometry(radius * 1.015, 0.007, 12, 100);
    const eqMat = new THREE.MeshBasicMaterial({
      color: isLightMode ? 0xc2410c : 0xf95721,
      transparent: true,
      opacity: isLightMode ? 0.55 : 0.35
    });
    const eqMesh = new THREE.Mesh(eqGeo, eqMat);
    eqMesh.rotation.x = Math.PI / 2;
    ringGroup.add(eqMesh);

    const orbitGeo = new THREE.TorusGeometry(radius * 1.06, 0.005, 12, 100);
    const orbitMat = new THREE.MeshBasicMaterial({
      color: isLightMode ? 0xea580c : 0xfb923c,
      transparent: true,
      opacity: isLightMode ? 0.40 : 0.22
    });
    const orbitMesh = new THREE.Mesh(orbitGeo, orbitMat);
    orbitMesh.rotation.x = Math.PI / 3;
    orbitMesh.rotation.y = Math.PI / 6;
    ringGroup.add(orbitMesh);

    // Glowing Orange Vertices / Nodes
    const posAttribute = icoGeometry.getAttribute('position');
    const vertexCount = posAttribute.count;
    const vertices: THREE.Vector3[] = [];
    const colors: number[] = [];

    const baseColor = new THREE.Color(isLightMode ? 0xc2410c : 0xf97316);
    const brightColor = new THREE.Color(isLightMode ? 0xea580c : 0xff461e);
    const hotColor = new THREE.Color(isLightMode ? 0xf97316 : 0xffd166);

    for (let i = 0; i < vertexCount; i++) {
      const v = new THREE.Vector3().fromBufferAttribute(posAttribute, i);
      vertices.push(v);
      const rand = Math.random();
      const c = rand > 0.8 ? hotColor : rand > 0.4 ? brightColor : baseColor;
      colors.push(c.r, c.g, c.b);
    }

    const pointsGeo = new THREE.BufferGeometry().setFromPoints(vertices);
    pointsGeo.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));

    // Canvas texture for smooth glowing points
    const createNodeTexture = (innerColor = 'rgba(255, 255, 255, 1)', midColor = 'rgba(234, 88, 12, 0.95)') => {
      const canvas = document.createElement('canvas');
      canvas.width = 64;
      canvas.height = 64;
      const ctx = canvas.getContext('2d');
      if (ctx) {
        const grad = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
        grad.addColorStop(0, innerColor);
        grad.addColorStop(0.3, midColor);
        grad.addColorStop(0.65, isLightMode ? 'rgba(194, 65, 12, 0.5)' : 'rgba(249, 87, 33, 0.4)');
        grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(32, 32, 32, 0, Math.PI * 2);
        ctx.fill();
      }
      return new THREE.CanvasTexture(canvas);
    };

    const pointsMat = new THREE.PointsMaterial({
      size: currentMode === 'advanced' ? 0.11 : 0.085,
      map: createNodeTexture(
        '#ffffff',
        isLightMode ? 'rgba(194, 65, 12, 1)' : 'rgba(249, 115, 22, 0.95)'
      ),
      vertexColors: true,
      transparent: true,
      opacity: 0.95,
      blending: isLightMode ? THREE.NormalBlending : THREE.AdditiveBlending,
      depthWrite: false
    });

    const pointsMesh = new THREE.Points(pointsGeo, pointsMat);
    globeGroup.add(pointsMesh);

    // City Beacons & Connected Threat Arcs
    const beaconMeshes: { mesh: THREE.Mesh; ring: THREE.Mesh; city: ThreatCityBeacon }[] = [];
    const beaconGroup = new THREE.Group();
    globeGroup.add(beaconGroup);

    const arcGroup = new THREE.Group();
    globeGroup.add(arcGroup);

    MONITORED_BEACONS.forEach((city) => {
      const pos = latLonToVector(city.lat, city.lon, radius);

      const isCritical = city.severity === 'critical';
      const beaconGeo = new THREE.SphereGeometry(isCritical ? 0.05 : 0.04, 16, 16);
      const beaconMat = new THREE.MeshBasicMaterial({
        color: isCritical ? 0xff2a00 : 0xf95721,
      });
      const beaconMesh = new THREE.Mesh(beaconGeo, beaconMat);
      beaconMesh.position.copy(pos);
      beaconGroup.add(beaconMesh);

      const pulseGeo = new THREE.RingGeometry(0.055, 0.08, 32);
      const pulseMat = new THREE.MeshBasicMaterial({
        color: isCritical ? 0xff461e : 0xfb923c,
        transparent: true,
        opacity: 0.7,
        side: THREE.DoubleSide
      });
      const pulseMesh = new THREE.Mesh(pulseGeo, pulseMat);
      pulseMesh.position.copy(pos.clone().multiplyScalar(1.01));
      pulseMesh.lookAt(pos.clone().multiplyScalar(2));
      beaconGroup.add(pulseMesh);

      beaconMeshes.push({ mesh: beaconMesh, ring: pulseMesh, city });
    });

    // Attack Arcs between key beacon locations
    const arcPairs = [
      ['syd', 'nyc'],
      ['nyc', 'sp'],
      ['sg', 'syd'],
      ['la', 'nyc'],
      ['mia', 'nyc'],
      ['sp', 'la']
    ];

    const arcMaterial = new THREE.LineBasicMaterial({
      color: isLightMode ? 0xc2410c : 0xff5722,
      transparent: true,
      opacity: isLightMode ? 0.9 : (currentMode === 'advanced' ? 0.8 : 0.6),
      linewidth: 1.5
    });

    arcPairs.forEach(([idA, idB], idx) => {
      const cityA = MONITORED_BEACONS.find(b => b.id === idA);
      const cityB = MONITORED_BEACONS.find(b => b.id === idB);
      if (cityA && cityB) {
        const vA = latLonToVector(cityA.lat, cityA.lon, radius);
        const vB = latLonToVector(cityB.lat, cityB.lon, radius);

        const mid = vA.clone().add(vB).multiplyScalar(0.5);
        const alt = radius * (1.2 + (idx % 3) * 0.08);
        mid.normalize().multiplyScalar(alt);

        const curve = new THREE.QuadraticBezierCurve3(vA, mid, vB);
        const curvePoints = curve.getPoints(32);
        const curveGeo = new THREE.BufferGeometry().setFromPoints(curvePoints);
        const arcLine = new THREE.Line(curveGeo, arcMaterial);
        arcGroup.add(arcLine);
      }
    });

    // Extra random arcs in advanced mode
    if (currentMode === 'advanced') {
      const extraArcMat = new THREE.LineBasicMaterial({
        color: 0xff8833,
        transparent: true,
        opacity: 0.5,
        linewidth: 1
      });
      for (let a = 0; a < 6; a++) {
        const iA = Math.floor(Math.random() * vertices.length);
        const iB = Math.floor(Math.random() * vertices.length);
        const vA = vertices[iA];
        const vB = vertices[iB];
        if (vA && vB && vA.distanceTo(vB) > 0.7) {
          const mid = vA.clone().add(vB).multiplyScalar(0.5);
          mid.normalize().multiplyScalar(radius * 1.25);
          const curve = new THREE.QuadraticBezierCurve3(vA, mid, vB);
          const curvePoints = curve.getPoints(24);
          const curveGeo = new THREE.BufferGeometry().setFromPoints(curvePoints);
          arcGroup.add(new THREE.Line(curveGeo, extraArcMat));
        }
      }
    }

    // Floating Threat Particle Cloud around sphere
    const particleCount = currentMode === 'advanced' ? 120 : 60;
    const particleGeo = new THREE.BufferGeometry();
    const particlePositions = new Float32Array(particleCount * 3);
    const particleColors = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount; i++) {
      const u = Math.random();
      const v = Math.random();
      const theta = u * 2.0 * Math.PI;
      const phi = Math.acos(2.0 * v - 1.0);
      const r = radius * (1.05 + Math.random() * 0.38);

      particlePositions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      particlePositions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      particlePositions[i * 3 + 2] = r * Math.cos(phi);

      const pColor = Math.random() > 0.5 ? brightColor : baseColor;
      particleColors[i * 3] = pColor.r;
      particleColors[i * 3 + 1] = pColor.g;
      particleColors[i * 3 + 2] = pColor.b;
    }

    particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    particleGeo.setAttribute('color', new THREE.BufferAttribute(particleColors, 3));

    const particleMat = new THREE.PointsMaterial({
      size: 0.045,
      map: createNodeTexture(
        '#ffffff',
        isLightMode ? 'rgba(194, 65, 12, 0.9)' : 'rgba(249, 115, 22, 0.8)'
      ),
      vertexColors: true,
      transparent: true,
      opacity: isLightMode ? 0.75 : 0.55,
      blending: isLightMode ? THREE.NormalBlending : THREE.AdditiveBlending,
      depthWrite: false
    });

    const particleCloud = new THREE.Points(particleGeo, particleMat);
    globeGroup.add(particleCloud);

    // Initial globe rotation
    globeGroup.rotation.x = targetRotationRef.current.x;
    globeGroup.rotation.y = targetRotationRef.current.y;

    // DYNAMIC CAMERA FITTING FUNCTION
    // Ensures the ball and its arcs fit fully and prominently on any screen aspect ratio
    const fitCameraToSphere = (w: number, h: number) => {
      const safeW = Math.max(10, w);
      const safeH = Math.max(10, h);
      const aspect = safeW / safeH;
      const vFovRad = (camera.fov * Math.PI) / 180;

      // Target bounding radius covering wireframe sphere, beacons, pulse rings, and outer arcs
      const targetBound = radius * 1.25;
      const distHeight = targetBound / Math.tan(vFovRad / 2);
      const distWidth = targetBound / (Math.tan(vFovRad / 2) * aspect);

      // Clean 9% safety breathing margin so the circle is prominent and fills the viewport cleanly without clipping
      const requiredZ = Math.max(distHeight, distWidth) * 1.09;
      camera.position.z = Math.max(4.8, requiredZ);
      camera.aspect = aspect;
      camera.updateProjectionMatrix();
      renderer.setSize(safeW, safeH);
    };

    // Fit camera on initial load
    fitCameraToSphere(initialWidth, initialHeight);

    // Interactive Drag & Inertia
    let prevMouseX = 0;
    let prevMouseY = 0;

    const onMouseDown = (e: MouseEvent) => {
      if (!interactive) return;
      isDraggingRef.current = true;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    };

    const onMouseMove = (e: MouseEvent) => {
      if (!isDraggingRef.current || !interactive) return;
      const deltaX = e.clientX - prevMouseX;
      const deltaY = e.clientY - prevMouseY;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;

      targetRotationRef.current.y += deltaX * 0.007;
      targetRotationRef.current.x += deltaY * 0.007;
      targetRotationRef.current.x = Math.max(-Math.PI / 2.3, Math.min(Math.PI / 2.3, targetRotationRef.current.x));
    };

    const onMouseUp = () => {
      isDraggingRef.current = false;
    };

    const onTouchStart = (e: TouchEvent) => {
      if (!interactive || e.touches.length === 0) return;
      isDraggingRef.current = true;
      prevMouseX = e.touches[0].clientX;
      prevMouseY = e.touches[0].clientY;
    };

    const onTouchMove = (e: TouchEvent) => {
      if (!isDraggingRef.current || !interactive || e.touches.length === 0) return;
      const deltaX = e.touches[0].clientX - prevMouseX;
      const deltaY = e.touches[0].clientY - prevMouseY;
      prevMouseX = e.touches[0].clientX;
      prevMouseY = e.touches[0].clientY;

      targetRotationRef.current.y += deltaX * 0.007;
      targetRotationRef.current.x += deltaY * 0.007;
      targetRotationRef.current.x = Math.max(-Math.PI / 2.3, Math.min(Math.PI / 2.3, targetRotationRef.current.x));
    };

    const onTouchEnd = () => {
      isDraggingRef.current = false;
    };

    container.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
    container.addEventListener('touchstart', onTouchStart, { passive: true });
    window.addEventListener('touchmove', onTouchMove, { passive: true });
    window.addEventListener('touchend', onTouchEnd);

    // Resize Handler via ResizeObserver
    const handleResize = () => {
      if (!container) return;
      const newWidth = container.clientWidth || 400;
      const newHeight = typeof height === 'number' ? height : container.clientHeight || 360;
      fitCameraToSphere(newWidth, newHeight);
    };

    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(container);

    // Animation Loop
    let animationFrameId: number;
    const clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Ambient idle rotation when user is not dragging - graceful, smooth kinetic movement
      if (!isDraggingRef.current) {
        targetRotationRef.current.y += 0.0014 * speedMultiplier;
        // Elegant constant tilt without disorienting wobble
        targetRotationRef.current.x = 0.22;
      }

      // Smooth interpolation damping
      globeGroup.rotation.y += (targetRotationRef.current.y - globeGroup.rotation.y) * 0.06;
      globeGroup.rotation.x += (targetRotationRef.current.x - globeGroup.rotation.x) * 0.06;

      // Subtle, synchronized glowing pulse on vertices and wireframe without geometrical detachment
      const glowFactor = 0.88 + Math.sin(elapsedTime * 2.2 * speedMultiplier) * 0.12;
      pointsMat.opacity = isLightMode ? Math.min(1, glowFactor + 0.1) : glowFactor;

      // Animate beacon pulse rings with smooth oscillation
      beaconMeshes.forEach(({ ring, city }, i) => {
        const isSelected = activeLocationId === city.id;
        const ringScale = isSelected 
          ? 1.0 + (Math.sin(elapsedTime * 3.0 * speedMultiplier + i) + 1) * 0.35 
          : 1.0 + (Math.sin(elapsedTime * 1.8 * speedMultiplier + i) + 1) * 0.18;
        ring.scale.set(ringScale, ringScale, ringScale);
      });

      // Gently rotate celestial particle cloud and secondary ring
      particleCloud.rotation.y -= 0.0008 * speedMultiplier;
      orbitMesh.rotation.z += 0.0012 * speedMultiplier;

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      cancelAnimationFrame(animationFrameId);
      resizeObserver.disconnect();

      container.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      container.removeEventListener('touchstart', onTouchStart);
      window.removeEventListener('touchmove', onTouchMove);
      window.removeEventListener('touchend', onTouchEnd);

      // Dispose geometries and materials cleanly
      icoGeometry.dispose();
      wireframeGeometry.dispose();
      wireframeMaterial.dispose();
      coreGeo.dispose();
      coreMat.dispose();
      pointsGeo.dispose();
      pointsMat.dispose();
      particleGeo.dispose();
      particleMat.dispose();
      arcMaterial.dispose();
      renderer.dispose();

      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [height, interactive, currentMode, speedMultiplier, theme]);

  return (
    <div className={`relative flex flex-col items-center justify-center select-none w-full ${className}`}>
      {/* Three.js Canvas Container */}
      <div
        ref={containerRef}
        style={{ height: typeof height === 'number' ? `${height}px` : height }}
        className="w-full relative flex items-center justify-center cursor-grab active:cursor-grabbing overflow-hidden"
      />

      {/* Segmented Controls (Default / Advanced) if requested */}
      {showControls && (
        <div className="flex flex-col items-center gap-2 mt-3 z-10 w-full px-4">
          <div className="inline-flex items-center p-1 rounded-xl bg-[#191716]/90 border border-[#2e2926] shadow-lg backdrop-blur-md text-xs font-mono">
            <button
              type="button"
              onClick={() => setMode('default')}
              className={`px-3.5 py-1.5 rounded-lg transition-all text-xs font-semibold cursor-pointer ${
                currentMode === 'default'
                  ? 'bg-[#292422] text-[#fafaf9] shadow-sm'
                  : 'text-[#a8a29e] hover:text-[#d6d3d1]'
              }`}
            >
              Default
            </button>
            <button
              type="button"
              onClick={() => setMode('advanced')}
              className={`px-3.5 py-1.5 rounded-lg transition-all text-xs font-semibold cursor-pointer ${
                currentMode === 'advanced'
                  ? 'bg-gradient-to-r from-[#ea580c] to-[#f95721] text-white shadow-[0_0_15px_rgba(249,87,33,0.45)]'
                  : 'text-[#a8a29e] hover:text-[#d6d3d1]'
              }`}
            >
              Advanced
            </button>
          </div>

          {caption && (
            <p className="text-xs text-[#a8a29e] font-sans text-center mt-0.5">
              {caption}
            </p>
          )}
        </div>
      )}
    </div>
  );
};
