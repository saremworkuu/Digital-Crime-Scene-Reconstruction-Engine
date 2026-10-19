import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { useApp } from '../store';

export const Forensic3DBackdrop: React.FC = () => {
  const { theme } = useApp();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (theme === 'light') {
      return;
    }

    const canvas = canvasRef.current;
    if (!canvas) return;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        canvas,
        alpha: true,
        antialias: false,
        powerPreference: 'low-power'
      });
    } catch {
      return;
    }

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, window.innerWidth / window.innerHeight, 0.1, 100);
    camera.position.z = 25;

    const setSize = () => {
      const w = window.innerWidth;
      const h = window.innerHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h, false);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
    };

    setSize();

    // 1. Subtle 3D Constellation Field of Cyber Forensic Nodes
    const nodeCount = 65;
    const positions = new Float32Array(nodeCount * 3);
    const initialPositions = new Float32Array(nodeCount * 3);
    const velocities: { x: number; y: number; z: number }[] = [];

    for (let i = 0; i < nodeCount; i++) {
      const x = (Math.random() - 0.5) * 40;
      const y = (Math.random() - 0.5) * 26;
      const z = (Math.random() - 0.5) * 18;

      positions[i * 3] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;

      initialPositions[i * 3] = x;
      initialPositions[i * 3 + 1] = y;
      initialPositions[i * 3 + 2] = z;

      velocities.push({
        x: (Math.random() - 0.5) * 0.006,
        y: (Math.random() - 0.5) * 0.006,
        z: (Math.random() - 0.5) * 0.004
      });
    }

    const pointsGeometry = new THREE.BufferGeometry();
    pointsGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    // Circular orange point texture
    const pointCanvas = document.createElement('canvas');
    pointCanvas.width = 32;
    pointCanvas.height = 32;
    const ctx = pointCanvas.getContext('2d');
    if (ctx) {
      const grad = ctx.createRadialGradient(16, 16, 0, 16, 16, 16);
      grad.addColorStop(0, 'rgba(255, 140, 70, 0.95)');
      grad.addColorStop(0.35, 'rgba(249, 87, 33, 0.5)');
      grad.addColorStop(0.8, 'rgba(234, 88, 12, 0.15)');
      grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(16, 16, 16, 0, Math.PI * 2);
      ctx.fill();
    }
    const texture = new THREE.CanvasTexture(pointCanvas);

    const pointsMaterial = new THREE.PointsMaterial({
      size: 0.65,
      map: texture,
      transparent: true,
      opacity: 0.45,
      blending: THREE.AdditiveBlending,
      depthWrite: false
    });

    const pointCloud = new THREE.Points(pointsGeometry, pointsMaterial);
    scene.add(pointCloud);

    // 2. Dynamic Connection Lines Between Proximity Nodes
    const maxConnections = 80;
    const linePositions = new Float32Array(maxConnections * 6);
    const lineGeometry = new THREE.BufferGeometry();
    lineGeometry.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));

    const lineMaterial = new THREE.LineBasicMaterial({
      color: 0xf95721,
      transparent: true,
      opacity: 0.12,
      linewidth: 1
    });

    const lineMesh = new THREE.LineSegments(lineGeometry, lineMaterial);
    scene.add(lineMesh);

    // 3. Subtle Floating Geometric Wireframes (Icosahedrons & Octahedrons) in 3D Depth
    const floatingPolys: { mesh: THREE.LineSegments; rotSpeed: { x: number; y: number; z: number }; origin: THREE.Vector3 }[] = [];
    const polyCount = 5;

    const icoWireGeo = new THREE.WireframeGeometry(new THREE.IcosahedronGeometry(1.2, 0));
    const octWireGeo = new THREE.WireframeGeometry(new THREE.OctahedronGeometry(1.0, 0));
    const polyMaterial = new THREE.LineBasicMaterial({
      color: 0xea580c,
      transparent: true,
      opacity: 0.15
    });

    for (let p = 0; p < polyCount; p++) {
      const geo = p % 2 === 0 ? icoWireGeo : octWireGeo;
      const polyMesh = new THREE.LineSegments(geo, polyMaterial);
      const px = ((p / (polyCount - 1)) - 0.5) * 32 + (Math.random() - 0.5) * 4;
      const py = (Math.random() - 0.5) * 18;
      const pz = -5 - Math.random() * 8;
      polyMesh.position.set(px, py, pz);
      scene.add(polyMesh);

      floatingPolys.push({
        mesh: polyMesh,
        rotSpeed: {
          x: (Math.random() - 0.5) * 0.008,
          y: (Math.random() - 0.5) * 0.008,
          z: (Math.random() - 0.5) * 0.006
        },
        origin: new THREE.Vector3(px, py, pz)
      });
    }

    // 4. Interactive Click Shockwave Rings
    interface Shockwave {
      mesh: THREE.LineLoop;
      radius: number;
      maxRadius: number;
      speed: number;
      opacity: number;
    }
    const shockwaves: Shockwave[] = [];
    const ringSegments = 48;
    const ringCircleGeo = new THREE.BufferGeometry();
    const ringCirclePositions = new Float32Array((ringSegments + 1) * 3);
    for (let i = 0; i <= ringSegments; i++) {
      const theta = (i / ringSegments) * Math.PI * 2;
      ringCirclePositions[i * 3] = Math.cos(theta);
      ringCirclePositions[i * 3 + 1] = Math.sin(theta);
      ringCirclePositions[i * 3 + 2] = 0;
    }
    ringCircleGeo.setAttribute('position', new THREE.BufferAttribute(ringCirclePositions, 3));

    // Mouse Parallax & World Space Target
    let targetMouseX = 0;
    let targetMouseY = 0;
    let currentMouseX = 0;
    let currentMouseY = 0;

    const mouseWorld = new THREE.Vector3(0, 0, 0);

    const handleMouseMove = (e: MouseEvent) => {
      const normX = (e.clientX / window.innerWidth - 0.5) * 2;
      const normY = (e.clientY / window.innerHeight - 0.5) * 2;
      targetMouseX = normX;
      targetMouseY = normY;

      // Approximate world coordinate on z=0 plane
      mouseWorld.set(normX * 16, -normY * 10, 0);
    };

    const handleClick = (e: MouseEvent) => {
      if (shockwaves.length >= 3) return; // Limit active ripples

      const normX = (e.clientX / window.innerWidth - 0.5) * 2;
      const normY = (e.clientY / window.innerHeight - 0.5) * 2;

      const ringMat = new THREE.LineBasicMaterial({
        color: 0xf95721,
        transparent: true,
        opacity: 0.45
      });
      const ringMesh = new THREE.LineLoop(ringCircleGeo, ringMat);
      ringMesh.position.set(normX * 18, -normY * 12, 0);
      ringMesh.scale.set(0.2, 0.2, 0.2);
      scene.add(ringMesh);

      shockwaves.push({
        mesh: ringMesh,
        radius: 0.2,
        maxRadius: 12,
        speed: 0.18,
        opacity: 0.45
      });
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    window.addEventListener('click', handleClick, { passive: true });
    window.addEventListener('resize', setSize);

    // Render loop
    let animId: number;
    let isVisible = true;

    const handleVisibilityChange = () => {
      isVisible = !document.hidden;
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);

    const animate = () => {
      animId = requestAnimationFrame(animate);
      if (!isVisible) return;

      currentMouseX += (targetMouseX - currentMouseX) * 0.04;
      currentMouseY += (targetMouseY - currentMouseY) * 0.04;

      camera.position.x = currentMouseX * 1.8;
      camera.position.y = -currentMouseY * 1.2;
      camera.lookAt(0, 0, 0);

      // Animate floating polyhedra
      for (const poly of floatingPolys) {
        poly.mesh.rotation.x += poly.rotSpeed.x;
        poly.mesh.rotation.y += poly.rotSpeed.y;
        poly.mesh.rotation.z += poly.rotSpeed.z;

        // Gentle floating oscillation
        poly.mesh.position.y = poly.origin.y + Math.sin(Date.now() * 0.001 + poly.origin.x) * 0.4;
      }

      // Animate Shockwaves
      for (let s = shockwaves.length - 1; s >= 0; s--) {
        const sw = shockwaves[s];
        sw.radius += sw.speed;
        sw.opacity *= 0.95;
        sw.mesh.scale.set(sw.radius, sw.radius, sw.radius);
        (sw.mesh.material as THREE.LineBasicMaterial).opacity = sw.opacity;

        if (sw.opacity < 0.02 || sw.radius > sw.maxRadius) {
          scene.remove(sw.mesh);
          (sw.mesh.material as THREE.LineBasicMaterial).dispose();
          shockwaves.splice(s, 1);
        }
      }

      // Move points gently + gentle interactive repulsion/attraction to mouse
      const pos = pointsGeometry.attributes.position.array as Float32Array;
      for (let i = 0; i < nodeCount; i++) {
        pos[i * 3] += velocities[i].x;
        pos[i * 3 + 1] += velocities[i].y;
        pos[i * 3 + 2] += velocities[i].z;

        // Subtle mouse influence
        const dx = pos[i * 3] - mouseWorld.x;
        const dy = pos[i * 3 + 1] - mouseWorld.y;
        const distSq = dx * dx + dy * dy;
        if (distSq < 25 && distSq > 0.1) {
          const force = (1 - Math.sqrt(distSq) / 5) * 0.02;
          pos[i * 3] += dx * force;
          pos[i * 3 + 1] += dy * force;
        }

        // Wrap boundaries
        if (pos[i * 3] > 20) pos[i * 3] = -20;
        if (pos[i * 3] < -20) pos[i * 3] = 20;
        if (pos[i * 3 + 1] > 13) pos[i * 3 + 1] = -13;
        if (pos[i * 3 + 1] < -13) pos[i * 3 + 1] = 13;
      }
      pointsGeometry.attributes.position.needsUpdate = true;

      // Update lines between nearby nodes
      let lineIndex = 0;
      const connectDistSq = 7.5 * 7.5;
      for (let i = 0; i < nodeCount && lineIndex < maxConnections; i++) {
        for (let j = i + 1; j < nodeCount && lineIndex < maxConnections; j++) {
          const dx = pos[i * 3] - pos[j * 3];
          const dy = pos[i * 3 + 1] - pos[j * 3 + 1];
          const dz = pos[i * 3 + 2] - pos[j * 3 + 2];
          const distSq = dx * dx + dy * dy + dz * dz;

          if (distSq < connectDistSq) {
            linePositions[lineIndex * 6] = pos[i * 3];
            linePositions[lineIndex * 6 + 1] = pos[i * 3 + 1];
            linePositions[lineIndex * 6 + 2] = pos[i * 3 + 2];

            linePositions[lineIndex * 6 + 3] = pos[j * 3];
            linePositions[lineIndex * 6 + 4] = pos[j * 3 + 1];
            linePositions[lineIndex * 6 + 5] = pos[j * 3 + 2];

            lineIndex++;
          }
        }
      }

      // Zero out unused line segments
      for (let k = lineIndex; k < maxConnections; k++) {
        linePositions[k * 6] = 0;
        linePositions[k * 6 + 1] = 0;
        linePositions[k * 6 + 2] = 0;
        linePositions[k * 6 + 3] = 0;
        linePositions[k * 6 + 4] = 0;
        linePositions[k * 6 + 5] = 0;
      }
      lineGeometry.attributes.position.needsUpdate = true;

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('click', handleClick);
      window.removeEventListener('resize', setSize);
      document.removeEventListener('visibilitychange', handleVisibilityChange);

      pointsGeometry.dispose();
      pointsMaterial.dispose();
      lineGeometry.dispose();
      lineMaterial.dispose();
      texture.dispose();
      icoWireGeo.dispose();
      octWireGeo.dispose();
      polyMaterial.dispose();
      ringCircleGeo.dispose();

      for (const sw of shockwaves) {
        (sw.mesh.material as THREE.LineBasicMaterial).dispose();
      }

      renderer.dispose();
    };
  }, [theme]);

  if (theme === 'light') {
    return null;
  }

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="fixed inset-0 pointer-events-none z-0 opacity-75"
      style={{ width: '100%', height: '100%' }}
    />
  );
};
